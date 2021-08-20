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

                    struct arp_t *arp = (void*) inner + sizeof(*inner);
                    if ((void*)arp + sizeof(*arp) <= data_end) {
                       bpf_trace_printk("Inner ARP op=%u 4-byte-src-mac=%x src-ip=%x\n",
                         arp->oper, (arp->sha), htonl(arp->spa) );

                       // filter for only request packets
                       if (arp->oper == 1) {
                          process_arp( ctx, htonl(vxlan->key), htonl(ip->saddr),
                                       (arp->sha), htonl(arp->spa) );
                       }
                    }
                 }
              }
           }
        } else {
           bpf_trace_printk("udp TOO SHORT?\n");
        }
      }
    }
  }
  return XDP_PASS;
}
