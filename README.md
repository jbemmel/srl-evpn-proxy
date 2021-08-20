# VXLAN data plane learning using eBPF: Using SR Linux as an EVPN proxy
Some traditional data center designs lack an EVPN control plane, but we can use SRL as a proxy

# Introduction
Most data center designs start small before they evolve. At small scale, it may make sense to manually configure static VXLAN tunnels between leaf switches, as illustrated [here](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-41/Network-Virtualization/Static-VXLAN-Tunnels/). There is nothing wrong with such an initial design, but as the fabric grows and the number of leaves reaches a certain threshold, having to touch every switch each time a device is added can get cumbersome and error prone.

The internet and most modern large scale data center designs use dynamic control plane protocols and volatile in-memory configuration to configure packet forwarding.

# Step 1: SRL as an EVPN proxy
By configuring an SRL node with the same VTEP tunnel IP and announcing a type 3 EVPN multicast route, we can send return traffic to static VXLAN endpoints.
However, as there is no data plane MAC learning, all MACs residing on such endpoints are effectively "unknown" as far as SRL is concerned, hence every packet to such MACs gets flooded to every VTEP in the fabric.

# Step 2: Adding eBPF based VXLAN aware MAC learning



# Sources used

* [Using map-in-map in BPF programs](https://hechao.li/2019/03/19/Use-Map-in-Map-in-BPF-programs-via-Libbpf/)
* [How to send perf events to Python userspace](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md#lesson-7-hello_perf_outputpy)
