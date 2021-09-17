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

#define IP_UDP 	 17
#define ETH_HLEN 14

/* eBPF program - working VXLAN ARP filter

  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )

	TODO VXLAN ARP packets have specific sizes - could filter on that too
*/
int vxlan_arp_filter(struct __sk_buff *skb) {
	// Shows up in: cat /sys/kernel/debug/tracing/trace_pipe
  bpf_trace_printk("vxlan_arp_filter got a packet len=%u\n",
    ((void *)(long)skb->data_end) - ((void *)(long)skb->data) );
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

  // check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) return DROP;

  // shift cursor forward for dynamic ip header size
  void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

	struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

  if (udp->dport != 4789) {
		bpf_trace_printk("udp_filter not UDP port 4789: %u\n", udp->dport );
		return DROP;
	}

	// Calculate payload offset and length
	// u32 vxlan_offset = ETH_HLEN + ip_header_length + sizeof(*udp);
	u32 vxlan_length = ip->tlen - ip_header_length - sizeof(*udp);
	if (vxlan_length < (ETH_HLEN+sizeof(struct arphdr))) {
		bpf_trace_printk("VXLAN length too short to be ARP: %u\n", vxlan_length );
		return DROP;
	}

  // skip VXLAN header
  _ = cursor_advance(cursor, sizeof(struct vxlan_t));
	struct ethernet_t *inner = cursor_advance(cursor, sizeof(*inner));

	// filter ARP packets (ethernet type = 0x0806)
	if (inner->type != 0x0806) {
		bpf_trace_printk("vxlan_arp_filter: Not ARP but ethertype %04x, dropping\n", inner->type );
		return DROP;
	}

	// keep the packet and send it to userspace returning -1
	bpf_trace_printk("vxlan_arp_filter: Sending ARP-in-VXLAN(IP+VXLAN=%u ARP=%u) to userspace\n",
	                  ip->tlen, vxlan_length );
	return KEEP;
}
