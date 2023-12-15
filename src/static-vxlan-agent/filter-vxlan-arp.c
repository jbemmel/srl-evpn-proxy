#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "vxlan_arp_filter"
#endif

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

// From linux/if_arp.h, not used
/*
struct arphdr
{
	__be16		ar_hrd;		// format of hardware address
	__be16		ar_pro;		// format of protocol address
	unsigned char	ar_hln;		// length of hardware address
	unsigned char	ar_pln;		// length of protocol address
	__be16		ar_op;		// ARP opcode (command)

	// Ethernet looks like this : This bit is variable sized however...
	unsigned char		ar_sha[6];	  // sender hardware address
	__be32 ar_sip;		            // sender IP address
	unsigned char		ar_tha[6];	  // target hardware address
	__be32 ar_tip;		            // target IP address
} __packed;
*/

#define IP_UDP 	 17
#define IP_TCP 	 6
#define ETH_HLEN 14

/* eBPF program - working VXLAN ARP filter, now also passes TCP timestamps

  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )

	TODO VXLAN ARP packets have specific sizes - could filter on that too
*/
int vxlan_arp_filter(struct __sk_buff *skb) {
	// Shows up in: cat /sys/kernel/debug/tracing/trace_pipe
  // Cannot access skb->wire_len directly here. Could use load_word?
  bpf_trace_printk("vxlan_arp_filter got a packet ingress_ifindex=%u ifindex=%u\n",
                    skb->ingress_ifindex, skb->ifindex );

  // Drop packets generated by local VTEP
  if ( skb->ingress_ifindex == 0 ) {
     bpf_trace_printk("vxlan_arp_filter: Dropping locally generated packet\n");
     // return bgp_rtt_monitor(skb);
     return DROP;
  }

  // invalid access: ((void *)(long)skb->data_end) - ((void *)(long)skb->data) );
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	// filter IPv4 packets (ethernet type = 0x0800), TODO support VLANs
	if (ethernet->type != 0x0800) {
		if (ethernet->type == 0x0806) {
			struct arp_t *arp = cursor_advance(cursor, sizeof(*arp));
			bpf_trace_printk("vxlan_arp_filter: Plain ARP(MAC=%llx) dropped\n",
			                  arp->sha /* ,htonl(arp->spa) */ );
		} else {
		   bpf_trace_printk("vxlan_arp_filter: not IPv4 but %x\n", ethernet->type );
		}
		return DROP;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

	// filter UDP packets (ip next protocol = 0x11) or TCP (0x6)
	if (ip->nextp != IP_UDP /* && ip->nextp != IP_TCP */ ) {
		bpf_trace_printk("vxlan_arp_filter: not UDP/VXLAN but %u\n", ip->nextp );
    return DROP;
	}

	//calculate ip header length
	//value to multiply * 4
	//e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	u32 ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

  // check ip header length against minimum
	if (ip_header_length < sizeof(*ip)) {
		bpf_trace_printk("vxlan_arp_filter: invalid IP header length %u\n", ip_header_length );
		return DROP;
	}

  // shift cursor forward for dynamic ip header size
  void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

  if (ip->nextp == IP_UDP) {
   	struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

    if (udp->dport != 4789) {
   		bpf_trace_printk("vxlan_arp_filter: not UDP port 4789: %u\n", udp->dport );
   		return DROP;
   	}

   	// Calculate payload offset and length
   	// u32 vxlan_offset = ETH_HLEN + ip_header_length + sizeof(*udp);
   	u32 vxlan_length = ip->tlen - ip_header_length - sizeof(*udp);
   	if (vxlan_length < (ETH_HLEN+sizeof(struct arp_t))) {
   		bpf_trace_printk("vxlan_arp_filter: VXLAN length too short to be ARP: %u\n", vxlan_length );
   		return DROP;
   	}

     // skip VXLAN header
    _ = cursor_advance(cursor, sizeof(struct vxlan_t));
   	struct ethernet_t *inner = cursor_advance(cursor, sizeof(*inner));

   	// filter ARP packets (ethernet type = 0x0806)
   	if (inner->type != 0x0806) {
   		bpf_trace_printk("vxlan_arp_filter: Not ARP but ethertype %x, dropping\n", inner->type );
   		return DROP;
   	}

    struct arp_t *arp = cursor_advance(cursor, sizeof(*arp));
   	// keep the packet and send it to userspace returning -1
   	// Limit is 3 variables
   	bpf_trace_printk("vxlan_arp_filter: Sending ARP-in-VXLAN(MAC=%llx) to userspace\n",
   	                  arp->sha /*,	htonl(arp->spa) */ );
   	return KEEP;
  } else { // else TCP

    /*
    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    // Look for BGP packets only
    if (tcp->dst_port == 179) {
      bpf_trace_printk("bgp_rtt_monitor: to BGP port source=%u\n", tcp->src_port );
    } else if (tcp->src_port == 179) {
      bpf_trace_printk("bgp_rtt_monitor: from BGP port dest=%u\n", tcp->dst_port );
    } else return DROP;

    // Look for enough room for timestamps
    int opt_len = tcp->offset << 2; // doff original, length in dwords
    if ( opt_len >= sizeof(*tcp)+12 ) {
      bpf_trace_printk("bgp_rtt_monitor: Found potential TS option in BGP packet opt_len=%u ktime=%llu\n",
        opt_len, bpf_ktime_get_ns() );
      return KEEP;
    }
    */
    return DROP;
  }
}