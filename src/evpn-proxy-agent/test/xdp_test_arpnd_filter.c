// arpnd filter

/*
 * eBPF program to attach to a spine facing interface, listening for VXLAN packets
 *
 * This sample version only looks for ARP packets, and sends the source MAC/IP
 * to userspace (once)
 */

// #define KBUILD_MODNAME "filter"

#include <linux/bpf.h>
// #include <bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

// Based on monitor.c
#include <bcc/proto.h>

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

// Helper to read a 6-byte MAC address
static u64 read_mac( unsigned char m[] ) {
  #define U(m) ((u64)m)
  return m[0]|(m[1]<<8)|(m[2]<<16)|(m[3]<<24)|(U(m[4])<<32)|(U(m[5])<<40);
}

// Event sent to userspace.
struct vxlan_arp_event_t {
    u32 vnid; // VXLAN VNID
    u32 vtep; // VTEP IPv4 source IP

    u64 src_mac; // Source MAC from ARP request
    u32 src_ip;  // Source IP from ARP request
};

// TODO use per-CPU BPF_MAP_TYPE_PERF_EVENT_ARRAY
BPF_PERF_OUTPUT(events);

/*
The inner maps are created by the userspace code

struct bpf_map_def SEC("maps") inner_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u64),    // MAC address
    .value_size = sizeof(__u32),  // VTEP IP
    .max_entries = 256,
};*/

/*
struct bpf_map_def SEC("maps") vnid_2_mactable = { // outer_map
    .type = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size = sizeof(__u32),   // VNID (24 bits)
    .value_size = sizeof(__u32), // Must be u32 because it's inner map id
    .max_entries = 128,          // i.e. max number of different VNIDs supported
};
*/

static void process_arp( struct xdp_md *ctx, u32 vnid, u32 vtep_ip, u64 src_mac, u32 src_ip ) {
  bpf_trace_printk( "process_arp VNID=%u VTEP=%x", vnid, vtep_ip );
  bpf_trace_printk( " MAC=%llx IP=%x\n", src_mac, src_ip );

  /* TODO:
     1. Lookup MAC table for VNID
     2. Lookup MAC in LRU table for VNID
     3. If not found: Send event to userspace (which will add it to the inner map)

     May have to write userspace in C too, any example in Python for working with map-in-map?
   */

   struct vxlan_arp_event_t arp_event = { vnid, vtep_ip, src_mac, src_ip };
   events.perf_submit(ctx, &arp_event, sizeof(arp_event));
}

int arpnd_filter(struct xdp_md *ctx) {
  bpf_trace_printk("arpnd_filter got a packet\n");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  // TODO support VLANs
  struct ethhdr *eth = data;
  if ((void*)eth + sizeof(*eth) <= data_end) {

    // Only process IPv4 VXLAN
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

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
                      return XDP_PASS;
                    }

                    struct arphdr *arp = (void*) inner + sizeof(*inner);
                    if ((void*)arp + sizeof(*arp) <= data_end) {
                       // Causes invalid op
                       // bpf_trace_printk("Inner ARP op=%u 4-byte-src-mac=%x src-ip=%x\n",
                       // arp->oper, (arp->sha), htonl(arp->spa) );

                       // filter for only request packets
                       if (arp->ar_op == __constant_htons(1)) {
                          process_arp( ctx, htonl(vxlan->key), htonl(ip->saddr),
                                       read_mac(arp->ar_sha), htonl(arp->ar_sip) );
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
         process_arp( ctx, 12345678, 0x01020304, 0x001122334455, 0x08080808 );
      }
    }
  }
  return XDP_PASS;
}
