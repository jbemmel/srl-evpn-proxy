# VXLAN data plane learning using eBPF: Using SR Linux as an EVPN proxy
Some traditional data center designs lack an EVPN control plane, but we can extend SRL to function as a proxy while transitioning to a fully dynamic EVPN fabric

# Introduction
Most data center designs start small before they evolve. At small scale, it may make sense to manually configure static VXLAN tunnels between leaf switches, as illustrated [here](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-41/Network-Virtualization/Static-VXLAN-Tunnels/). There is nothing wrong with such an initial design, but as the fabric grows and the number of leaves reaches a certain threshold, having to touch every switch each time a device is added can get cumbersome and error prone.

The internet and most modern large scale data center designs use dynamic control plane protocols and volatile in-memory configuration to configure packet forwarding.

# Step 1: SRL as an EVPN proxy
By configuring an SRL node with the same VTEP tunnel IP and announcing a type 3 EVPN multicast route, we can send return traffic to static VXLAN endpoints.
However, as there is no data plane MAC learning, all MACs residing on such endpoints are effectively "unknown" as far as SRL is concerned, hence every packet to such MACs gets flooded to every VTEP in the fabric.

# Step 2: Adding eBPF based VXLAN aware MAC learning from ARP requests
The idea is to create an eBPF XDP program to filter out VXLAN packets on a given fabric interface inside the default network instance (associated with a MAC VRF (L2) or an IP VRF (L3) overlay service). The program selects only VXLAN packets (UDP port 4789) containing ARP requests, and uses a "map of maps" (BPF_MAP_TYPE_HASH_OF_MAPS) to lookup the LRU MAC table for the given VNID. If the MAC is unknown, a perf event (BPF_PERF_OUTPUT) is submitted to userspace, containing the VNID, VTEP IP(v4), source MAC and source IP. The Python userspace program then uses BGP EVPN to advertise a route (type 2 for MAC-VRF, type 5 for IP-VRF) to the fabric (locally or towards a route reflector).

## Other options considered
I looked into attaching to the loopback TCP connection between the datapath (sr_xdp_lc_1) and the ARP/ND manager process (sr_arp_nd_mgr); there are 3 connections, and one of them received a packet containing the ARP request from a host. However, as neither the VTEP IP nor the VXLAN VNID are available in this message, there appears to be no easy way to associate the source MAC from these ARP packets with the correct service.

# Sources used

* [Using map-in-map in BPF programs](https://hechao.li/2019/03/19/Use-Map-in-Map-in-BPF-programs-via-Libbpf/)
* [How to send perf events to Python userspace](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md#lesson-7-hello_perf_outputpy)
* [Processing VXLAN packets in BPF](https://github.com/iovisor/bcc/tree/master/examples/networking/tunnel_monitor)
