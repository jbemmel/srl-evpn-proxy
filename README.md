# VXLAN data plane learning using eBPF: Using SR Linux as an EVPN proxy
Some traditional data center designs lack an EVPN control plane, but we can extend SRL to function as a proxy while transitioning to a fully dynamic EVPN fabric
![plot](images/EVPN_Agent.png)

# Introduction
Most data center designs start small before they evolve. At small scale, it may make sense to manually configure static VXLAN tunnels between leaf switches, as illustrated [here](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-41/Network-Virtualization/Static-VXLAN-Tunnels/) and implemented on the 2 virtual lab nodes on the left side. There is nothing wrong with such an initial design, but as the fabric grows and the number of leaves reaches a certain threshold, having to touch every switch each time a device is added can get cumbersome and error prone.

The internet and most modern large scale data center designs use dynamic control plane protocols and volatile in-memory configuration to configure packet forwarding. BGP is a popular choice, and the Ethernet VPN address family (EVPN [RFC8365](https://datatracker.ietf.org/doc/html/rfc8365)) can support both L2 and L3 overlay services. However, legacy fabrics continue to support business critical applications, and there is a desire to keep doing so without service interruptions, and with minimal changes. So how can we move to the new dynamic world of EVPN based data center fabrics, while transitioning gradually and smoothly from these static configurations?

## Option 1: SRL nodes as EVPN proxies
By configuring an SRL node with the same VTEP tunnel IP and announcing a type 3 EVPN multicast route, we can send return traffic to static VXLAN endpoints.
However, as there is no data plane MAC learning, all MACs residing on such endpoints are effectively "unknown" as far as SRL is concerned, hence every packet to such MACs gets flooded to every VTEP in the fabric. Not very elegant nor practical.

# Solution: Implement an EVPN proxy agent
By adding a BGP speaker application to an SR Linux node, we can advertise EVPN routes on behalf of legacy VTEP devices with static configuration. Furthermore, by observing datapath VXLAN traffic from such nodes, we can dynamically discover MAC addresses and VTEP endpoint IPs.

This Github repo implements such an approach, using the following components:
* The [Ryu BGP speaker library](https://ryu.readthedocs.io/en/latest/library_bgp_speaker_ref.html) and [packet parsing classes](https://ryu.readthedocs.io/en/latest/library_packet.html)
* Google gRPC framework, [modified to support eventlet](https://github.com/jbemmel/grpc) (used by Ryu)
* VXLAN ARP snooping using [Extended Berkeley Packet Filters(eBPF)](https://prototype-kernel.readthedocs.io/en/latest/bpf/) filters

## Step 1: Adding an eBPF based VXLAN packet filter to capture ARP packets
The idea is to create an eBPF program to filter out VXLAN packets on a given fabric interface inside the srbase network instance (associated with a MAC VRF (L2) or an IP VRF (L3) overlay service). The filter program selects only VXLAN packets (UDP port 4789) containing ARP packets (requests or responses).

```Python
Rx( packet ) {
if (packet==VXLAN) && (packet.inner == ARP) {
  forward to Python userspace program
}
```

## Step 2: Send out EVPN routes (multicast, RT2 for each MAC/IP) on behalf of static VTEPs
The Python userspace program receives filtered VXLAN ARP packets and uses BGP EVPN to advertise a route (type 2 for MAC-VRF, type 5 for IP-VRF[TODO]) to the fabric (locally or towards a route reflector). It participates in the EVPN fabric and only advertises routes for VTEPs that are not sending EVPN routes themselves.

As it was found that Ryu implicitly assumes the sending endpoint is also the tunnel endpoint, [some minor changes](https://github.com/jbemmel/srl-evpn-proxy/tree/main/ryu_enhancements) had to be made to allow for arbitrary tunnel endpoint IPs in multicast routes.

# Lab prototype demo
Using [Containerlab](https://containerlab.srlinux.dev/), the topology described above is easily deployed:

```
make # to build the custom 'srl/evpn-proxy-agent' Docker container
containerlab deploy -t static-vxlan.lab
```

Out of the box, the EVPN proxy agent is disabled; h1 can ping h2 and h3 can ping h4 (after giving the nodes enough time to boot):

```
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-lab-h1 ping 10.0.0.102 -c2
PING 10.0.0.102 (10.0.0.102) 56(84) bytes of data.
64 bytes from 10.0.0.102: icmp_seq=1 ttl=64 time=2.35 ms
64 bytes from 10.0.0.102: icmp_seq=2 ttl=64 time=6.27 ms

--- 10.0.0.102 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms
rtt min/avg/max/mdev = 2.351/4.312/6.274/1.962 ms
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-lab-h3 ping 10.0.0.104 -c2
PING 10.0.0.104 (10.0.0.104) 56(84) bytes of data.
64 bytes from 10.0.0.104: icmp_seq=1 ttl=64 time=0.975 ms
64 bytes from 10.0.0.104: icmp_seq=2 ttl=64 time=0.958 ms

--- 10.0.0.104 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms
rtt min/avg/max/mdev = 0.958/0.966/0.975/0.032 ms
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
* GRPC and eventlet don't play nicely together, see https://github.com/grpc/grpc/issues/15923 ; 2020 [patch available](https://github.com/Akrog/grpc/blob/eventlet/src/python/grpcio/grpc/experimental/eventlet.py)
