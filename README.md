# Evolving from static VXLAN: Using SR Linux as an EVPN proxy (featuring eBPF based data plane ARP learning)
Some traditional data center designs lack an EVPN control plane, but we can extend SRL to function as a proxy while transitioning to a fully dynamic EVPN fabric
![plot](images/EVPN_Agent.png)

# Introduction
Most data center designs start small before they evolve. At small scale, it may make sense to manually configure static VXLAN tunnels between leaf switches, as illustrated [here](https://docs.nvidia.com/networking-ethernet-software/cumulus-linux-41/Network-Virtualization/Static-VXLAN-Tunnels/) and implemented on the 2 virtual lab nodes on the left side. There is nothing wrong with such an initial design, but as the fabric grows and the number of leaves reaches a certain threshold, having to touch every switch each time a device is added can get cumbersome and error prone.

The internet and most modern large scale data center designs use dynamic control plane protocols and volatile in-memory configuration to configure packet forwarding. BGP is a popular choice, and the Ethernet VPN address family (EVPN [RFC8365](https://datatracker.ietf.org/doc/html/rfc8365)) can support both L2 and L3 overlay services. However, legacy fabrics continue to support business critical applications, and there is a desire to keep doing so without service interruptions, and with minimal changes. So how can we move to the new dynamic world of EVPN based data center fabrics, while transitioning gradually and smoothly from these static configurations?

## Announcing EVPN multicast routes on behalf of static VXLAN VTEPs
By configuring an SRL node to announce type 3 EVPN multicast routes for each L2 service and each remote VTEP, we can send return traffic to static VXLAN endpoints.
Without dataplane MAC learning, all MACs residing on such endpoints are effectively "unknown" as far as SRL is concerned, hence every packet to such MACs gets flooded to every VTEP in the fabric. This may be acceptible for point-to-point connections, but for point-to-multipoint this quickly becomes inefficient.

Configure SRL1 with a VXLAN agent representing static VTEPs 1.1.1.1 and 1.1.1.2:
```
enter candidate
/network-instance default protocols vxlan-agent
  admin-state enable
  source-address ${/interface[name=lo0]/subinterface[index=0]/ipv4/address/ip-prefix|_.split('/')[0]}
  local-as 65000
  peer-as 65000
commit stay
/show network-instance default protocols bgp neighbor 1.1.1.4 received-routes evpn

/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1
  vxlan-agent
    admin-state enable
    evi ${/network-instance[name=mac-vrf-evi10]/protocols/bgp-evpn/bgp-instance[id=1]/evi}
    vni ${/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/ingress/vni}
    static-vtep 1.1.1.1 { }
    static-vtep 1.1.1.2 { }

commit stay
```

This enables reachability between endpoints behind either static or dynamic EVPN VTEPs:
```
docker exec -it clab-static-vxlan-spine-lab-h3 ping 10.0.0.101
```
However, packets sent towards MACs behind static VTEPs are flooded to all VTEPs:
```
monitor from state /tunnel vxlan-tunnel vtep 1.1.1.{1,2} statistics out-packets
```
```
[2021-10-14 16:55:38.665943]: update /tunnel/vxlan-tunnel/vtep[address=1.1.1.1]/statistics/out-packets:469
[2021-10-14 16:55:38.666652]: update /tunnel/vxlan-tunnel/vtep[address=1.1.1.2]/statistics/out-packets:469
[2021-10-14 16:55:47.213625]: update /tunnel/vxlan-tunnel/vtep[address=1.1.1.1]/statistics/out-packets:479
[2021-10-14 16:55:47.214112]: update /tunnel/vxlan-tunnel/vtep[address=1.1.1.2]/statistics/out-packets:479
[2021-10-14 16:55:57.232972]: update /tunnel/vxlan-tunnel/vtep[address=1.1.1.1]/statistics/out-packets:490
[2021-10-14 16:55:57.234006]: update /tunnel/vxlan-tunnel/vtep[address=1.1.1.2]/statistics/out-packets:490
```
Notice how SRL1 is sending an equal amount of packets towards all other VTEPs

# Static MAC route solution
Flooding of traffic towards these "unknown" MACs can be avoided by configuring them statically:
```
/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1
vxlan-agent
static-vtep 1.1.1.1 { 
  mac-addresses [ 00:11:22:33:44:03 ]
}
commit stay
```

This causes the VXLAN agent to announce an EVPN RT2 MAC route, enabling all dynamic VTEPs to identify the correct destination VTEP.

## Flood protection agent
A separate custom CLI extension can be used to simplify the provisioning of dynamically learnt MAC addresses, and associating them with a static VTEP.

# Dynamic learning solution
By observing datapath VXLAN traffic from static VTEP nodes, we can dynamically discover MAC addresses and VTEP endpoint IPs.

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
Using [Containerlab](https://containerlab.srlinux.dev/), the following topology can be deployed:
![plot](images/EVPN_proxy_lab_with_spine.png)

```
bash -c "$(curl -sL https://get-clab.srlinux.dev)" # install Containerlab, version 0.18 or higher
git clone --recurse-submodules https://github.com/jbemmel/srl-evpn-proxy.git
make all # to build the custom 'srl/evpn-proxy-agent' Docker container
cd labs/spine-leaf && sudo containerlab deploy -t static-vxlan-with-spine.lab
```
All VXLAN traffic is forwarded via a single spine.
Out of the box, the EVPN proxy agent is disabled; h1 can ping h2 and h3 can ping h4 (after giving the nodes enough time to boot):

```
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.102 -c2
PING 10.0.0.102 (10.0.0.102) 56(84) bytes of data.
64 bytes from 10.0.0.102: icmp_seq=1 ttl=64 time=2.35 ms
64 bytes from 10.0.0.102: icmp_seq=2 ttl=64 time=6.27 ms

--- 10.0.0.102 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms
rtt min/avg/max/mdev = 2.351/4.312/6.274/1.962 ms
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h3 ping 10.0.0.104 -c2
PING 10.0.0.104 (10.0.0.104) 56(84) bytes of data.
64 bytes from 10.0.0.104: icmp_seq=1 ttl=64 time=0.975 ms
64 bytes from 10.0.0.104: icmp_seq=2 ttl=64 time=0.958 ms

--- 10.0.0.104 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms
rtt min/avg/max/mdev = 0.958/0.966/0.975/0.032 ms

# Cannot ping from static to EVPN VTEP
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c2
PING 10.0.0.103 (10.0.0.103) 56(84) bytes of data.
From 10.0.0.101 icmp_seq=1 Destination Host Unreachable
From 10.0.0.101 icmp_seq=2 Destination Host Unreachable

--- 10.0.0.103 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 15ms
pipe 2
```

The EVPN VTEPs [have been added to the static configuration](https://github.com/jbemmel/srl-evpn-proxy/blob/main/labs/spine-leaf/cumulus1_interfaces#L42) and static underlay routes make them reachable, however return traffic gets dropped on the SRL nodes as there is no valid route.

We can enable the EVPN proxy on SRL1 (or SRL2, or both):
```
enter candidate
/network-instance default protocols 
bgp {
  group vxlan-agent {
    admin-state enable
    peer-as 65000 !!! iBGP
    ipv4-unicast {
       admin-state disable
    }
    ipv6-unicast {
       admin-state disable
    }
    evpn {
       admin-state enable
    }
    route-reflector {
      client true
      cluster-id ${/network-instance[name=default]/protocols/bgp/router-id}
    }
  }
  neighbor ${/interface[name=lo0]/subinterface[index=0]/ipv4/address/ip-prefix|_.split('/')[0]} {
    description "Local EVPN proxy agent for static VXLAN"
    admin-state enable
    peer-group vxlan-agent
  }
  trace-options {
     flag packets {
         modifier detail
     }
     flag update {
         modifier detail
     }
  }
}
vxlan-agent
  admin-state enable
  source-address ${/interface[name=lo0]/subinterface[index=0]/ipv4/address/ip-prefix|_.split('/')[0]}
  local-as 65000
  peer-as 65000
  proof-of-concept {
    include-ip true
    auto-discover-static-vteps true
    vxlan-arp-learning-interfaces [ e1-1 ]
  }
commit stay
/show network-instance default protocols bgp neighbor 1.1.1.4 received-routes evpn

/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 
  vxlan-agent
    admin-state enable
    evi ${/network-instance[name=mac-vrf-evi10]/protocols/bgp-evpn/bgp-instance[id=1]/evi}
    vni ${/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/ingress/vni}
    static-vtep 1.1.1.1 { }

commit stay
/show network-instance default protocols bgp neighbor 1.1.1.4 received-routes evpn
```
This configures the local SRL node to be a route reflector too, such that it will update other EVPN VTEPs with any proxy routes. If we now retry the ping:
```
commit stay                                                                                                                                                                                                        
Lookup state path=${/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/ingress/vni} _root=/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/ingress parts=['', 'tunnel-interface[name=vxlan0]', 'vxlan-interface[index=0]', 'ingress', 'vni']
root=/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/ingress leaf=vni -> 11189196 type=<class 'int'>
All changes have been committed. Starting new transaction.
--{ + candidate shared default }--[ network-instance default protocols experimental-bgp-evpn-proxy ]--                                                                                                             
A:srl1# quit                                                                                                                                                                                                       
Connection to clab-static-vxlan-spine-lab-srl1 closed.
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c2
PING 10.0.0.103 (10.0.0.103) 56(84) bytes of data.
64 bytes from 10.0.0.103: icmp_seq=1 ttl=64 time=1038 ms
64 bytes from 10.0.0.103: icmp_seq=2 ttl=64 time=5.96 ms

--- 10.0.0.103 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 33ms
rtt min/avg/max/mdev = 5.960/521.770/1037.581/515.811 ms, pipe 2
```

Looking at the EVPN routes received from the custom proxy application:
```
jeroen@bembox:~/srlinux/srl-evpn-proxy$ ssh admin@clab-static-vxlan-spine-lab-srl1
Warning: Permanently added 'clab-static-vxlan-lab-srl1,2001:172:20:20::3' (ECDSA) to the list of known hosts.
Last login: Tue Aug 24 22:04:55 2021 from 2001:172:20:20::1
Using configuration file(s): ['/home/admin/.srlinuxrc']
Welcome to the srlinux CLI.
Type 'help' (and press <ENTER>) if you need any help using this.
--{ + running }--[  ]--                                                                                                                                                                                            
A:srl1# show network-instance default protocols bgp neighbor 1.1.1.4 received-routes evpn                                                                                           
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Peer        : 1.1.1.4, remote AS: 65000, local AS: 65000
Type        : static
Description : Local EVPN proxy agent
Group       : leaves
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Status codes: u=used, *=valid, >=best, x=stale
Origin codes: i=IGP, e=EGP, ?=incomplete
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type 2 MAC-IP Advertisement Routes
+--------+------------------------------+------------+-------------------+------------------------------+------------------------------+------------------------------+---------+------------------------------+
| Status |     Route-distinguisher      |   Tag-ID   |    MAC-address    |          IP-address          |           Next-Hop           |             MED              | LocPref |             Path             |
+========+==============================+============+===================+==============================+==============================+==============================+=========+==============================+
| u*>    | 1.1.1.1:57069                | 0          | AA:C1:AB:1D:2C:6E | 10.0.0.101                   | 1.1.1.1                      | -                            | 100     |                              |
+--------+------------------------------+------------+-------------------+------------------------------+------------------------------+------------------------------+---------+--

Type 3 Inclusive Multicast Ethernet Tag Routes
+--------+--------------------------------------+------------+---------------------+--------------------------------------+--------------------------------------+---------+-----+
| Status |         Route-distinguisher          |   Tag-ID   |    Originator-IP    |               Next-Hop               |                 MED                  | LocPref |                 Path                 |
+========+======================================+============+=====================+======================================+======================================+=========+=====+
| u*>    | 1.1.1.1:57069                        | 0          | 1.1.1.4             | 1.1.1.1                              | -                                    | 100     |                                      |
+--------+--------------------------------------+------------+---------------------+--------------------------------------+--------------------------------------+---------+-----+
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0 Ethernet Auto-Discovery routes 0 used, 0 valid
1 MAC-IP Advertisement routes 1 used, 1 valid
1 Inclusive Multicast Ethernet Tag routes 1 used, 1 valid
0 Ethernet Segment routes 0 used, 0 valid
0 IP Prefix routes 0 used, 0 valid
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```
In the log file at /var/log/srlinux/stdout/srl_evpn_proxy.log we see:
```
...
22:05:10,606 root INFO ARP packet:ethernet=ethernet(dst='02:6a:2c:ff:00:02',ethertype=2048,src='aa:c1:ab:68:e1:e8')
22:05:10,607 root INFO ARP packet:ipv4=ipv4(csum=44804,dst='1.1.1.5',flags=0,header_length=5,identification=51347,offset=0,option=None,proto=17,src='1.1.1.1',tos=0,total_length=78,ttl=63,version=4)
22:05:10,608 root INFO ARP packet:udp=udp(csum=32319,dst_port=4789,src_port=40050,total_length=58)
22:05:10,608 root INFO ARP packet:vxlan=vxlan(vni=11189196)
22:05:10,608 root INFO vni = 11189196
22:05:10,608 root INFO ARP packet:ethernet=ethernet(dst='ff:ff:ff:ff:ff:ff',ethertype=2054,src='aa:c1:ab:cc:3b:ad')
22:05:10,608 root INFO ARP packet:arp=arp(dst_ip='10.0.0.103',dst_mac='00:00:00:00:00:00',hlen=6,hwtype=1,opcode=1,plen=4,proto=2048,src_ip='10.0.0.101',src_mac='aa:c1:ab:cc:3b:ad')
22:05:10,609 root INFO ARP request from static VTEP: aa:c1:ab:cc:3b:ad 10.0.0.101
22:05:10,609 root INFO Adding VRF...RD=1.1.1.1:57069 RT=65000:57069
22:05:10,609 bgpspeaker.api.base INFO API method vrf.create called with args: {'route_dist': '1.1.1.1:57069', 'import_rts': ['65000:57069'], 'export_rts': ['65000:57069'], 'site_of_origins': None, 'route_family': 'evpn', 'multi_exit_disc': None}
22:05:10,616 root INFO Adding EVPN multicast route...
22:05:10,616 bgpspeaker.api.base INFO API method evpn_prefix.add_local called with args: {'route_type': 'multicast_etag', 'route_dist': '1.1.1.1:57069', 'next_hop': '1.1.1.1', 'tunnel_type': 'vxlan', 'ethernet_tag_id': 0, 'ip_addr': '1.1.1.1', 'vni': 11189196, 'pmsi_tunnel_type': 6, 'tunnel_endpoint_ip': '1.1.1.1'}
22:05:10,617 root INFO Announcing EVPN MAC route...evpn_vteps={'1.1.1.5': 65000, '1.1.1.7': 65000}
22:05:10,617 bgpspeaker.api.base INFO API method evpn_prefix.add_local called with args: {'route_type': 'mac_ip_adv', 'route_dist': '1.1.1.1:57069', 'next_hop': '1.1.1.1', 'tunnel_type': 'vxlan', 'esi': 0, 'ethernet_tag_id': 0, 'mac_addr': 'aa:c1:ab:cc:3b:ad', 'ip_addr': '10.0.0.101', 'vni': 11189196}
```
Meaning SRL1 received an ARP request sent by static VTEP 1.1.1.1 (CVX1), the VNI matches the configured proxy value and the MAC/IP pair is advertised as a RT2. Q.E.D.

Once SRL1 learns a MAC/IP route, it sends it to SRL2 such that a ping from H1 to H4 should now work too:
```
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.104 -c2
PING 10.0.0.104 (10.0.0.104) 56(84) bytes of data.
64 bytes from 10.0.0.104: icmp_seq=1 ttl=64 time=34.9 ms
64 bytes from 10.0.0.104: icmp_seq=2 ttl=64 time=2.39 ms

--- 10.0.0.104 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms
rtt min/avg/max/mdev = 2.393/18.640/34.888/16.248 ms
```

In case a host first tries to reach H4 without trying H3, the datapath will not work; a multicast route must first be established. Without a specific MAC/IP route, traffic will still get flooded until the proxy on SRL1 learns the correct VTEP:
```
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h2 ping 10.0.0.104 -c2
PING 10.0.0.104 (10.0.0.104) 56(84) bytes of data.
64 bytes from 10.0.0.104: icmp_seq=1 ttl=64 time=2068 ms
64 bytes from 10.0.0.104: icmp_seq=2 ttl=64 time=1043 ms

--- 10.0.0.104 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 26ms
rtt min/avg/max/mdev = 1042.896/1555.218/2067.540/512.322 ms, pipe 2
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h2 ping 10.0.0.103 -c1
PING 10.0.0.103 (10.0.0.103) 56(84) bytes of data.
64 bytes from 10.0.0.103: icmp_seq=1 ttl=64 time=2.31 ms

--- 10.0.0.103 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.306/2.306/2.306/0.000 ms
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h2 ping 10.0.0.104 -c2
PING 10.0.0.104 (10.0.0.104) 56(84) bytes of data.
64 bytes from 10.0.0.104: icmp_seq=1 ttl=64 time=3.24 ms
64 bytes from 10.0.0.104: icmp_seq=2 ttl=64 time=2.63 ms

--- 10.0.0.104 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms
rtt min/avg/max/mdev = 2.633/2.935/3.238/0.307 ms
```
This could be avoided by running the EVPN proxy on every SRL node.

## Static MAC address entries
Instead of dynamic learning via ARP, it is also possible to configure static MAC entries for each VTEP:
```
/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 
  vxlan-agent
  static-vtep 1.1.1.1 {
    static-macs [ 00:11:22:33:44:55 ]
  }
```
This causes the agent to send out a Type 2 EVPN route for the given MAC address(es):
```
A:srl1# /show network-instance default protocols bgp neighbor 1.1.1.4 received-routes evpn                                                                                                                         
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Peer        : 1.1.1.4, remote AS: 65000, local AS: 65000
Type        : static
Description : Local EVPN proxy agent
Group       : vxlan-agent
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Status codes: u=used, *=valid, >=best, x=stale
Origin codes: i=IGP, e=EGP, ?=incomplete
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type 2 MAC-IP Advertisement Routes
+--------+------------------------------+------------+-------------------+------------------------------+------------------------------+------------------------------+--------+
| Status |     Route-distinguisher      |   Tag-ID   |    MAC-address    |          IP-address          |           Next-Hop           |             MED              | LocPref |              Path             |
+========+==============================+============+===================+==============================+==============================+==============================+========+
| u*>    | 1.1.1.1:57069                | 0          | 00:11:22:33:44:55 | 0.0.0.0                      | 1.1.1.1                      | -                            | 100     |                              |
| u*>    | 1.1.1.2:57069                | 0          | 00:11:22:33:44:66 | 0.0.0.0                      | 1.1.1.2                      | -                            | 100     |                              |
+--------+------------------------------+------------+-------------------+------------------------------+------------------------------+------------------------------+----+----
Type 3 Inclusive Multicast Ethernet Tag Routes
+--------+--------------------------------------+------------+---------------------+--------------------------------------+--------------------------------------+---------+---+
| Status |         Route-distinguisher          |   Tag-ID   |    Originator-IP    |               Next-Hop               |                 MED                  | LocPref |                 Path                 |
+========+======================================+============+=====================+======================================+======================================+=========+===+
| u*>    | 1.1.1.1:57069                        | 0          | 1.1.1.4             | 1.1.1.1                              | -                                    | 100     |                                      |
| u*>    | 1.1.1.2:57069                        | 0          | 1.1.1.4             | 1.1.1.2                              | -                                    | 100     |                                      |
+--------+--------------------------------------+------------+---------------------+--------------------------------------+--------------------------------------+---------+---+
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0 Ethernet Auto-Discovery routes 0 used, 0 valid
2 MAC-IP Advertisement routes 2 used, 2 valid
2 Inclusive Multicast Ethernet Tag routes 2 used, 2 valid
0 Ethernet Segment routes 0 used, 0 valid
0 IP Prefix routes 0 used, 0 valid
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--{ running }--[ network-instance mac-vrf-evi10 protocols bgp-evpn ]--
```

# Packet tracing using Linux kernel trace events
The Linux kernel supports trace events, which can be used to track packets as they move through the fabric.
As root:
```
echo 1 > /sys/kernel/debug/tracing/events/net/netif_receive_skb/enable
cat /sys/kernel/debug/tracing/trace_pipe
    <idle>-0     [030] ..s. 17429.831685: netif_receive_skb: dev=eth0 skbaddr=ffff99a3b231d600 len=52
    <idle>-0     [030] .Ns. 17429.831694: netif_receive_skb: dev=eth0 skbaddr=ffff99a3b231d600 len=52
```

We can filter for SR Linux interfaces only:
```
echo 'name ~ "e1-*"' > /sys/kernel/debug/tracing/events/net/netif_receive_skb/filter
```

To track specific packets - like ARP packets for example - we can filter on specific lengths:
```
17:46:16.622045 02:a5:e4:ff:00:01 > 02:80:2e:ff:00:03, ethertype IPv4 (0x0800), length 92: (tos 0x0, ttl 255, id 15, offset 0, flags [DF], proto UDP (17), length 78)
    1.1.1.5.51309 > 1.1.1.1.4789: VXLAN, flags [I] (0x08), vni 11189196
aa:c1:ab:e1:98:8e > aa:c1:ab:ee:23:c1, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Reply 10.0.0.103 is-at aa:c1:ab:e1:98:8e, length 28
	0x0000:  4500 004e 000f 4000 ff11 7788 0101 0105  E..N..@...w.....
	0x0010:  0101 0101 c86d 12b5 003a 0000 0800 0000  .....m...:......
	0x0020:  aabb cc00 aac1 abee 23c1 aac1 abe1 988e  ........#.......
	0x0030:  0806 0001 0800 0604 0002 aac1 abe1 988e  ................
	0x0040:  0a00 0067 aac1 abee 23c1 0a00 0065       ...g....#....e
17:46:16.626903 02:80:2e:ff:00:03 > 02:a5:e4:ff:00:01, ethertype IPv4 (0x0800), length 92: (tos 0x0, ttl 63, id 54742, offset 0, flags [none], proto UDP (17), length 78)
    1.1.1.1.39822 > 1.1.1.5.4789: VXLAN, flags [I] (0x08), vni 11189196
aa:c1:ab:ee:23:c1 > aa:c1:ab:e1:98:8e, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Reply 10.0.0.101 is-at aa:c1:ab:ee:23:c1, length 28
	0x0000:  4500 004e d5d6 0000 3f11 a1c1 0101 0101  E..N....?.......
	0x0010:  0101 0105 9b8e 12b5 003a d052 0800 0000  .........:.R....
	0x0020:  aabb cc00 aac1 abe1 988e aac1 abee 23c1  ..............#.
	0x0030:  0806 0001 0800 0604 0002 aac1 abee 23c1  ..............#.
	0x0040:  0a00 0065 aac1 abe1 988e 0a00 0067       ...e.........g

[linuxadmin@srl1 ~]$ sudo tcpdump -i e1-2 -nnveX arp
tcpdump: listening on e1-2, link-type EN10MB (Ethernet), snapshot length 262144 bytes
17:53:38.480219 aa:c1:ab:e1:98:8e > aa:c1:ab:ee:23:c1, ethertype ARP (0x0806), length 42: Ethernet (len 6), IPv4 (len 4), Request who-has 10.0.0.101 tell 10.0.0.103, length 28
	0x0000:  0001 0800 0604 0001 aac1 abe1 988e 0a00  ................
	0x0010:  0067 0000 0000 0000 0a00 0065            .g.........e
```

As illustrated, ARP-in-VXLAN packets are (14+78)+(14+28) = 134 bytes; without VXLAN encapsulation, they are 72

```
echo 'name ~ "e1-*" && (len == 72 || len == 134)' > /sys/kernel/debug/tracing/events/net/netif_receive_skb/filter
```

# EVPN MAC Mobility
EVPN MAC Mobility procedures are defined in [RFC7432](https://datatracker.ietf.org/doc/html/rfc7432#section-7.7) and amount to adding a sequence number extended community to RT2 updates. Ryu supports the parsing and generation of these attributes, but the code currently does not use them; a patch was created to change that.

## EVPN MAC Mobility in case of multiple proxies
For redundancy, multiple proxies can be instantiated, and any one of them can assume responsibility for announcing EVPN MAC IP routes as they are discovered. Each proxy will listen for RT2 updates from other proxies, and if an announcement for a MAC with a different VTEP is received (TODO: with a higher sequence number? currently always), the proxy will withdraw its own route.

Each proxy uses its own IP as originator when sending the RT3 multicast route; this allows EVPN peers to pick the best route consistently.
For example, with an EVPN proxy running locally at 1.1.1.6, SRL2 picks the routes from the proxy at SRL1 due to its lower originator IP
```
A:srl2# show network-instance default protocols bgp neighbor 1.1.1.5 received-routes evpn                                                                                                                          
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Peer        : 1.1.1.5, remote AS: 65000, local AS: 65000
Type        : static
Description : None
Group       : leaves
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Status codes: u=used, *=valid, >=best, x=stale
Origin codes: i=IGP, e=EGP, ?=incomplete
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type 2 MAC-IP Advertisement Routes
+--------+------------------------------+------------+-------------------+------------------------------+------------------------------+------------------------------+---------+------------------------------+
| Status |     Route-distinguisher      |   Tag-ID   |    MAC-address    |          IP-address          |           Next-Hop           |             MED              | LocPref |             Path             |
+========+==============================+============+===================+==============================+==============================+==============================+=========+==============================+
| u*>    | 1.1.1.1:57069                | 0          | AA:C1:AB:1D:2C:6E | 10.0.0.101                   | 1.1.1.1                      | -                            | 100     |                              |
| u*>    | 1.1.1.2:57069                | 0          | AA:C1:AB:DC:39:CE | 10.0.0.102                   | 1.1.1.2                      | -                            | 100     |                              |
| u*>    | 1.1.1.5:57069                | 0          | AA:C1:AB:9C:80:6C | 0.0.0.0                      | 1.1.1.5                      | -                            | 100     |                              |
+--------+------------------------------+------------+-------------------+------------------------------+------------------------------+------------------------------+---------+------------------------------+
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type 3 Inclusive Multicast Ethernet Tag Routes
+--------+--------------------------------------+------------+---------------------+--------------------------------------+--------------------------------------+---------+--------------------------------------+
| Status |         Route-distinguisher          |   Tag-ID   |    Originator-IP    |               Next-Hop               |                 MED                  | LocPref |                 Path                 |
+========+======================================+============+=====================+======================================+======================================+=========+======================================+
| u*>    | 1.1.1.1:57069                        | 0          | 1.1.1.4             | 1.1.1.1                              | -                                    | 100     |                                      |
| u*>    | 1.1.1.2:57069                        | 0          | 1.1.1.4             | 1.1.1.2                              | -                                    | 100     |                                      |
| u*>    | 1.1.1.5:57069                        | 0          | 1.1.1.5             | 1.1.1.5                              | -                                    | 100     |                                      |
+--------+--------------------------------------+------------+---------------------+--------------------------------------+--------------------------------------+---------+--------------------------------------+
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0 Ethernet Auto-Discovery routes 0 used, 0 valid
3 MAC-IP Advertisement routes 3 used, 3 valid
3 Inclusive Multicast Ethernet Tag routes 3 used, 3 valid
0 Ethernet Segment routes 0 used, 0 valid
0 IP Prefix routes 0 used, 0 valid
```
The above also provides insight into which routes are 'native' EVPN ( next hop == originator IP ), and which ones are proxied

## Testing MAC Mobility
We can test MAC mobility by swapping the MACs of H1 and H2, and then ping from H2 to H3:
```bash
cat > test_mac_move.sh << EOF
docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c2
MAC1=\`docker exec -it clab-static-vxlan-spine-lab-h1 ip a show dev eth1 | awk '/ether/{ print \$2 }' | head -1\`
MAC2=\`docker exec -it clab-static-vxlan-spine-lab-h2 ip a show dev eth1 | awk '/ether/{ print \$2 }' | head -1\`
docker exec -it clab-static-vxlan-spine-lab-h1 ip link set address \$MAC2 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h1 ip addr flush dev eth1
docker exec -it clab-static-vxlan-spine-lab-h1 ip addr add 10.0.0.102/24 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h2 ip link set address \$MAC1 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h2 ip addr flush dev eth1
docker exec -it clab-static-vxlan-spine-lab-h2 ip addr add 10.0.0.101/24 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h2 ping 10.0.0.103 -c2
EOF
chmod +x ./test_mac_move.sh 
bash -c ./test_mac_move.sh
```

Similarly, we can move the MAC to EVPN (H4 attached to SRL2) and repeat the test:
```bash
cat > test_mac_move_2_evpn.sh << EOF
docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c2
MAC1=\`docker exec -it clab-static-vxlan-spine-lab-h1 ip a show dev eth1 | awk '/ether/{ print \$2 }' | head -1\`
MAC2=\`docker exec -it clab-static-vxlan-spine-lab-h4 ip a show dev eth1 | awk '/ether/{ print \$2 }' | head -1\`
docker exec -it clab-static-vxlan-spine-lab-h1 ip link set address \$MAC2 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h4 ip link set address \$MAC1 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h4 ping 10.0.0.103 -c2
EOF
chmod +x ./test_mac_move_2_evpn.sh 
bash -c ./test_mac_move_2_evpn.sh
```
In the latter case, when the EVPN proxy receives a MAC update for a MAC it has advertised, it withdraws the route if the VTEP and/or IP has changed.

## A note on sFlow sampling
On physical SRL nodes, sFlow sampling could be used to learn MAC/IP routes, instead of eBPF filters. If required and over time, the sampling frequency could be reduced, or a target could be set on the number of VTEPs to discover before transitioning to a forwarding-only mode

# Using BFD for SLA monitoring
SR Linux supports BFD on static routes, which can be used to monitor VTEP-to-VTEP connectivity (using a configurable interval):

SRL1
```
${PEER=1.1.1.7}
```
SRL2
```
${PEER=1.1.1.5}
```

```
enter candidate                        
/bfd subinterface system0.0 admin-state enable
/network-instance default static-routes 
route ${PEER}/32
admin-state enable
next-hop-group peer-vtep-${PEER}
/network-instance default next-hop-groups group peer-vtep-${PEER} nexthop 0 
ip-address ${PEER}
admin-state enable
failure-detection enable-bfd local-address ${/interface[name=system0]/subinterface[index=0]/ipv4/address/ip-prefix| _.split('/')[0] }
commit stay
```

This results in an active BFD session which checks connectivity every [interval] seconds (default 1s):
```
A:srl1# info from state /bfd                                                                                                                                                                                       
    bfd {
        total-bfd-sessions 1
        total-unmatched-bfd-packets 31
        subinterface system0.0 {
            admin-state enable
            desired-minimum-transmit-interval 1000000
            required-minimum-receive 1000000
            detection-multiplier 3
            minimum-echo-receive-interval 0
        }
        network-instance default {
            peer 16385 {
                oper-state up
                local-address 1.1.1.5
                remote-address 1.1.1.7
                remote-discriminator 16386
                subscribed-protocols STATIC_ROUTE
                session-state UP
                remote-session-state UP
                last-state-transition "12 minutes ago"
                failure-transitions 0
                local-diagnostic-code DETECTION_TIMEOUT
                remote-diagnostic-code NO_DIAGNOSTIC
                remote-minimum-receive-interval 1000000
                remote-control-plane-independent false
                active-transmit-interval 1000000
                active-receive-interval 1000000
                remote-multiplier 3
                async {
                    last-packet-transmitted "4 seconds ago"
                    last-packet-received "4 seconds ago"
                    transmitted-packets 1763
                    received-packets 1494
                    up-transitions 2
                }
            }
        }
    }
```

## Other options considered
I looked into attaching to the loopback TCP connection between the datapath (sr_xdp_lc_1) and the ARP/ND manager process (sr_arp_nd_mgr); there are 3 connections, and one of them received a packet containing the ARP request from a host. However, as neither the VTEP IP nor the VXLAN VNID are available in this message, there appears to be no easy way to associate the source MAC from these ARP packets with the correct service.

I tried attaching an XDP program to e1-2 (with BPF_PERF_OUTPUT events to communicate with userspace containing the VNID, VTEP IP(v4), source MAC and source IP), but Linux returns a permission denied error

One could use TC ingress/egress filters to distinguish various cases; the raw socket receives both incoming and outgoing VXLAN packets. It may be possible to determine this from the [sk_buff](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L5146) struct.

As an optimization, I considered using a "map of maps" (BPF_MAP_TYPE_HASH_OF_MAPS) to lookup the LRU MAC table for the given VNID. If the MAC is found, the packet is dropped.
However, ARP packets are rare enough to not represent a large burden on the CPU, and a simple VXLAN ARP filter is easier to program.

I tried collecting sFlow samples, but the SR Linux container image only seems to send counter samples, not packet samples.

eBPF ARP filter could reduce packets sent to userspace by implementing a hashmap of ARPs already forwarded; the Python userspace could program a list of EVPN VTEPs to ignore

# Sources used

* [Using map-in-map in BPF programs](https://hechao.li/2019/03/19/Use-Map-in-Map-in-BPF-programs-via-Libbpf/)
* [How to send perf events to Python userspace](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md#lesson-7-hello_perf_outputpy)
* [Processing VXLAN packets in BPF](https://github.com/iovisor/bcc/tree/master/examples/networking/tunnel_monitor)
* [Ryu packet parsing](https://ryu.readthedocs.io/en/latest/library_packet.html)

# Issues encountered
* gRPC and eventlet don't play nicely together, see https://github.com/grpc/grpc/issues/15923 ; 2020 [patch available](https://github.com/Akrog/grpc/blob/eventlet/src/python/grpcio/grpc/experimental/eventlet.py) and [merged with master](https://github.com/jbemmel/grpc)
* gRPC parallel builds obfuscate compiler errors; [use](https://github.com/jbemmel/srl-evpn-proxy/blob/main/Dockerfile#L30) 'GRPC_PYTHON_BUILD_EXT_COMPILER_JOBS=1' to build serially
* Network namespaces can be tricky to work with in Python
