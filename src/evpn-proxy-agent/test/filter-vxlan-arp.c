#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#include <linux/bpf.h>
// #include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define DROP 0  // drop the packet
#define KEEP -1 // keep the packet and send it to userspace returning -1

// From linux/if_arp.h, just used for size calculation
struct arphdr
{
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/

	 /*
	  *	 Ethernet looks like this : This bit is variable sized however...
	  */
	unsigned char		ar_sha[6];	  /* sender hardware address	*/
	__be32 ar_sip;		            /* sender IP address		*/
	unsigned char		ar_tha[6];	  /* target hardware address	*/
	__be32 ar_tip;		            /* target IP address		*/
} __packed;

/*eBPF program.
  Filter UDP VXLAN packets containing an ARP request

  The program is loaded as PROG_TYPE_SOCKET_FILTER and attached to a raw socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int vxlan_arp_filter(struct __sk_buff *skb) {

	bpf_trace_printk("arpnd_filter got a packet\n");

	// XXX does not work - direct access not allowed
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

	// TODO support VLANs
	struct ethhdr *eth = data;
	if ((void*)eth + sizeof(*eth) <= data_end) {

		// Only process IPv4 VXLAN
		if (eth->h_proto != __constant_htons(ETH_P_IP)) return DROP;

		// TODO ARP-over-VXLAN packets have a fixed size; check for that early
		struct iphdr *ip = data + sizeof(*eth);
		if ((void*)ip + sizeof(*ip) <= data_end) {
			if (ip->protocol == IPPROTO_UDP) {
				struct udphdr *udp = (void*)ip + sizeof(*ip);
				if ((void*)udp + sizeof(*udp) <= data_end) {
					 bpf_trace_printk("arpnd_filter rx udp port %u -> %u size %u\n", ntohs(udp->source),
							ntohs(udp->dest), data_end - data );
					 if (udp->dest == __constant_htons(4789)) {
							// Switching to BCC code here; Plumgrid example doesn't use ntohs() on UDP dest port??
							struct vxlan_t *vxlan = (void*)udp + sizeof(*udp);
							if ((void*)vxlan + sizeof(*vxlan) <= data_end) {
								 bpf_trace_printk("VXLAN vni %u\n", ntohl(vxlan->key) );

								 struct ethhdr *inner = (void*)vxlan + sizeof(*vxlan);
								 if ((void*)inner + sizeof(*inner) <= data_end) {

										// Only process ARP packets
										if ( inner->h_proto != __constant_htons(ETH_P_ARP) ) {
											bpf_trace_printk("Not ARP but %x -> ignoring\n", htons(inner->h_proto) );
											return DROP;
										}

										struct arphdr *arp = (void*) inner + sizeof(*inner);
										if ((void*)arp + sizeof(*arp) <= data_end) {
											 // Causes invalid op
											 // bpf_trace_printk("Inner ARP op=%u 4-byte-src-mac=%x src-ip=%x\n",
											 // arp->oper, (arp->sha), htonl(arp->spa) );

											 // filter for only request packets
											 if (arp->ar_op == __constant_htons(1)) {
													return KEEP;
											 }
										}
								 }
							}
					 }
				} else {
					 bpf_trace_printk("udp TOO SHORT?\n");
				}
			} else if (ip->protocol == IPPROTO_ICMP) {
				 // for debugging on Ubuntu
				 bpf_trace_printk("ICMP debug message\n");
				 return KEEP;
			}
		}
	}

  return DROP;
}

#define IP_UDP 	 17
#define ETH_HLEN 14

/* eBPF program - working VXLAN ARP filter

  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )

	TODO VXLAN ARP packets have specific sizes - could filter on that too
*/
int udp_filter(struct __sk_buff *skb) {
  bpf_trace_printk("udp_filter got a packet\n");
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	// filter IPv4 packets (ethernet type = 0x0800), TODO support VLANs
	if (ethernet->type != 0x0800) return DROP;

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter UDP packets (ip next protocol = 0x11)
	if (ip->nextp != IP_UDP) return DROP;

	//calculate ip header length
	//value to multiply * 4
	//e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	u32 ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

        //check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) return DROP;

  //shift cursor forward for dynamic ip header size
  void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

  if (udp->dport != 4789) {
		bpf_trace_printk("udp_filter not UDP port 4789: %u\n", udp->dport );
		return DROP; // debug
	}

	// Calculate payload offset and length
	// u32 vxlan_offset = ETH_HLEN + ip_header_length + sizeof(*udp);
	u32 vxlan_length = ip->tlen - ip_header_length - sizeof(*udp);
	if (vxlan_length < (ETH_HLEN+sizeof(struct arphdr))) return DROP;

  // skip VXLAN header
  _ = cursor_advance(cursor, sizeof(struct vxlan_t));
	struct ethernet_t *inner = cursor_advance(cursor, sizeof(*inner));

	// filter ARP packets (ethernet type = 0x0806)
	if (inner->type != 0x0806) return DROP;

	//keep the packet and send it to userspace returning -1
	return KEEP;
}

/**
 * Could make things even simpler using the __sk_buff data? see
 * https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L5146
 *
 * Nope, does _not_ work: direct access to these fields is denied
 */
int vxlan_filter(struct __sk_buff *skb) {
  return skb->protocol == IPPROTO_UDP &&
	  (skb->local_port == 4789 || skb->remote_port == __constant_htons(4789)) ? KEEP : DROP;
}
