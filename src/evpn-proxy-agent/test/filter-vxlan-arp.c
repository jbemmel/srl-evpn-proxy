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

// From linux/if_arp.h, XDP programs need fixed offsets
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

	// Since Linux 4.7 direct access is allowed
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
