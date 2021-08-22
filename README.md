# VXLAN data plane learning using eBPF: Using SR Linux as an EVPN proxy
Some traditional data center designs lack an EVPN control plane, but we can extend SRL to function as a proxy while transitioning to a fully dynamic EVPN fabric

# Introduction
Most data center designs start small before they evolve. At small scale, it may make sense to manually configure static VXLAN tunnels between leaf switches, as illustrated [here](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-41/Network-Virtualization/Static-VXLAN-Tunnels/). There is nothing wrong with such an initial design, but as the fabric grows and the number of leaves reaches a certain threshold, having to touch every switch each time a device is added can get cumbersome and error prone.

The internet and most modern large scale data center designs use dynamic control plane protocols and volatile in-memory configuration to configure packet forwarding.

# Step 1: SRL as an EVPN proxy
By configuring an SRL node with the same VTEP tunnel IP and announcing a type 3 EVPN multicast route, we can send return traffic to static VXLAN endpoints.
However, as there is no data plane MAC learning, all MACs residing on such endpoints are effectively "unknown" as far as SRL is concerned, hence every packet to such MACs gets flooded to every VTEP in the fabric.

# Step 2: Adding eBPF based VXLAN aware MAC learning from ARP packets
The idea is to create an eBPF program to filter out VXLAN packets on a given fabric interface inside the srbase network instance (associated with a MAC VRF (L2) or an IP VRF (L3) overlay service). The filter program selects only VXLAN packets (UDP port 4789) containing ARP packets (requests or responses).

The Python userspace program then uses BGP EVPN to advertise a route (type 2 for MAC-VRF, type 5 for IP-VRF) to the fabric (locally or towards a route reflector).
It participates in the EVPN fabric and only advertises routes for VTEPs that are not sending EVPN routes themselves.

```Python
Rx packet event( dst_vtep_IP, src_vtep_IP, VXLAN_VNI, arp_is_req, arp_src_mac, arp_dst_mac, arp_src_ip, arp_dst_ip ) {
For an enabled L2 VNI:

```

## Other options considered
I looked into attaching to the loopback TCP connection between the datapath (sr_xdp_lc_1) and the ARP/ND manager process (sr_arp_nd_mgr); there are 3 connections, and one of them received a packet containing the ARP request from a host. However, as neither the VTEP IP nor the VXLAN VNID are available in this message, there appears to be no easy way to associate the source MAC from these ARP packets with the correct service.

I tried attaching an XDP program to e1-2 (with BPF_PERF_OUTPUT events to communicate with userspace containing the VNID, VTEP IP(v4), source MAC and source IP), but Linux returns a permission denied error

One could use TC ingress/egress filters to distinguish various cases; the raw socket receives both incoming and outgoing VXLAN packets. It may be possible to determine this from the [sk_buff](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L5146) struct.

As an optimization, I considered using a "map of maps" (BPF_MAP_TYPE_HASH_OF_MAPS) to lookup the LRU MAC table for the given VNID. If the MAC is found, the packet is dropped.
However, ARP packets are rare enough to not represent a large burden on the CPU, and a simple VXLAN ARP filter is easier to program.

I tried collecting sFlow samples, but the SR Linux container image only seems to send counter samples, not packet samples.

# Sources used

* [Using map-in-map in BPF programs](https://hechao.li/2019/03/19/Use-Map-in-Map-in-BPF-programs-via-Libbpf/)
* [How to send perf events to Python userspace](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md#lesson-7-hello_perf_outputpy)
* [Processing VXLAN packets in BPF](https://github.com/iovisor/bcc/tree/master/examples/networking/tunnel_monitor)
* [Ryu packet parsing](https://ryu.readthedocs.io/en/latest/library_packet.html)

# Issues encountered
* GRPC and eventlet don't play nicely together, see https://github.com/grpc/grpc/issues/15923
