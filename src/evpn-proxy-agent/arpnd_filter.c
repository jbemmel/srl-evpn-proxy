// arpnd filter

/*
 eBPF program to attach on loopback in srbase, listening for communication between
 SRL processes: sr_xdp_lc_(*) => sr_arp_nd_mg
*/

// #define KBUILD_MODNAME "filter"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
// #include <linux/udp.h>
#include <linux/tcp.h>

int arpnd_filter(struct xdp_md *ctx) {
  bpf_trace_printk("arpnd_filter got a packet\n");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void*)eth + sizeof(*eth) <= data_end) {
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) <= data_end) {
      if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) <= data_end) {
           bpf_trace_printk("tcp port %u\n", ntohs(tcp->source), ntohs(tcp->dest) );
        } else {
           bpf_trace_printk("tcp TOO SHORT?\n");
        }
      }
    }
  }
  return XDP_PASS;
}
