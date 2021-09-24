# VXLAN Agent EVPN control plane demo scenario
![plot](images/EVPN_proxy_lab_with_spine.png)
## Installation
```
bash -c "$(curl -sL https://get-clab.srlinux.dev)" # install Containerlab, version 0.18 or higher
git clone --recurse-submodules https://github.com/jbemmel/srl-evpn-proxy
cd srl-evpn-proxy
make all # to build the custom 'srl/evpn-proxy-agent' Docker container and the base image
cd labs/spine-leaf && sudo containerlab deploy -t static-vxlan-with-spine.lab
```

After a minute or two, this results in a setup containing 2 Cumulus nodes with static VXLAN configuration, and 2 SR Linux nodes with dynamic EVPN VXLAN.
Both CVX1 and CVX2 have the EVPN VTEPs SRL1 and SRL2 listed in their config, but the reverse path is disabled.

## Baseline validation
H1 (on CVX1) can ping H2 (on CVX2) and H3(on SRL1) can ping H4(on SRL2), but no other flows work.
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

# Cannot ping from static to EVPN VTEP H1->H3
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c2
PING 10.0.0.103 (10.0.0.103) 56(84) bytes of data.
From 10.0.0.101 icmp_seq=1 Destination Host Unreachable
From 10.0.0.101 icmp_seq=2 Destination Host Unreachable

--- 10.0.0.103 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 15ms
```

## Enable VXLAN proxy agent
On SRL1, a BGP peering group is configured to enable an iBGP EVPN connection with the local VXLAN proxy agent:
```
A:srl1# /network-instance default                                                                                                                                                                                  
--{ running }--[ network-instance default ]--                                                                                                                                                                      
A:srl1# info protocols bgp group vxlan-agent                                                                                                                                                                       
    protocols {
        bgp {
            group vxlan-agent {
                admin-state enable
                peer-as 65000
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
                    cluster-id 1.1.1.5
                }
            }
        }
    }
```

To enable the local agent to run on lo0:
```
enter candidate
/network-instance default protocols vxlan-agent
  admin-state enable
  source-address ${/interface[name=lo0]/subinterface[index=0]/ipv4/address/ip-prefix|_.split('/')[0]}
  local-as 65000
  peer-as 65000
commit stay
```

This should result in a new peer:
```
A:srl1# /show network-instance default protocols bgp neighbor                                                                                                                                                      
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
BGP neighbor summary for network-instance "default"
Flags: S static, D dynamic, L discovered by LLDP, B BFD enabled, - disabled, * slow
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
+-----------------------+---------------------------------+-----------------------+--------+------------+------------------+------------------+----------------+---------------------------------+
|       Net-Inst        |              Peer               |         Group         | Flags  |  Peer-AS   |      State       |      Uptime      |    AFI/SAFI    |         [Rx/Active/Tx]          |
+=======================+=================================+=======================+========+============+==================+==================+================+=================================+
| default               | 1.1.1.4                         | vxlan-agent           | S      | 65000      | established      | 0d:0h:0m:12s     | evpn           | [0/0/4]                         |
| default               | 1.1.1.7                         | leaves                | S      | 65000      | established      | 0d:0h:3m:50s     | ipv4-unicast   | [4/3/4]                         |
|                       |                                 |                       |        |            |                  |                  | evpn           | [2/2/2]                         |
+-----------------------+---------------------------------+-----------------------+--------+------------+------------------+------------------+----------------+---------------------------------+
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Summary:
2 configured neighbors, 2 configured sessions are established,0 disabled peers
0 dynamic peers
--{ + candidate shared default }--[ network-instance default protocols vxlan-agent ]--
```

Note how the agent is not sending any EVPN routes yet, as we have not configured any remote VTEPs. It is receiving EVPN routes for other dynamic VTEPs in the fabric.

Once we enable the agent for a particular L2 EVPN service, it starts to advertise a type 3 multicast route for every static VTEP configured:
```
/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 
  vxlan-agent
    admin-state enable
    static-vxlan-remoteips [ 1.1.1.1 ] # CVX1 VTEP (only)
    evi ${/network-instance[name=mac-vrf-evi10]/protocols/bgp-evpn/bgp-instance[id=1]/evi}
    vni ${/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/ingress/vni}
commit stay
```

### Verify static VTEP proxy routes
```
A:srl1# show /network-instance default protocols bgp neighbor 1.1.1.4 received-routes evpn                                                                                                                         
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Peer        : 1.1.1.4, remote AS: 65000, local AS: 65000
Type        : static
Description : Local EVPN proxy agent for static VXLAN
Group       : vxlan-agent
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Status codes: u=used, *=valid, >=best, x=stale
Origin codes: i=IGP, e=EGP, ?=incomplete
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Type 3 Inclusive Multicast Ethernet Tag Routes
+--------+--------------------------------------+------------+---------------------+--------------------------------------+--------------------------------------+---------+--------------------------------------+
| Status |         Route-distinguisher          |   Tag-ID   |    Originator-IP    |               Next-Hop               |                 MED                  | LocPref |                 Path                 |
+========+======================================+============+=====================+======================================+======================================+=========+======================================+
| u*>    | 1.1.1.1:57069                        | 0          | 1.1.1.4             | 1.1.1.1                              | -                                    | 100     |                                      |
+--------+--------------------------------------+------------+---------------------+--------------------------------------+--------------------------------------+---------+--------------------------------------+
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0 Ethernet Auto-Discovery routes 0 used, 0 valid
0 MAC-IP Advertisement routes 0 used, 0 valid
1 Inclusive Multicast Ethernet Tag routes 1 used, 1 valid
0 Ethernet Segment routes 0 used, 0 valid
0 IP Prefix routes 0 used, 0 valid
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--{ + candidate shared default }--[ network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 vxlan-agent ]--
```
Note how this 'proxy route' is announced with a Route-distinguisher(RD) based on the VTEP IP and the EVI value, like a "regular" EVPN VTEP would do. The originator IP is set to the VXLAN proxy's IP, such that operators can distinguish proxy routes from "regular" EVPN routes. The originator IP is also used as a tie breaker in case of multiple proxies announcing the same route.

Once the multicast route is advertised, the service becomes operational:
```
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c1
PING 10.0.0.103 (10.0.0.103) 56(84) bytes of data.
64 bytes from 10.0.0.103: icmp_seq=1 ttl=64 time=10.7 ms

--- 10.0.0.103 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 10.673/10.673/10.673/0.000 ms
```

The MAC address is not being learned, so packets with unknown MAC destinations get flooded to all VTEPs in the mac vrf:
```
A:srl1# info from state /network-instance mac-vrf-evi10 bridge-table mac-table                                                                                                                                     
    network-instance mac-vrf-evi10 {
        bridge-table {
            mac-table {
                mac AA:C1:AB:24:99:E7 {
                    destination-type sub-interface
                    destination-index 2
                    type learnt
                    last-update "a minute ago"
                    destination ethernet-1/2.0
                    is-protected false
                }
                mac AA:C1:AB:52:E9:80 {
                    destination-type vxlan
                    destination-index 12939368018
                    type evpn
                    last-update "4 minutes ago"
                    destination "vxlan-interface:vxlan0.0 vtep:1.1.1.7 vni:11189196"
                    is-protected false
                }
            }
        }
    }
--{ + running }--[  ]--
```

Because the multicast route is reflected to other EVPN VTEPs, we can also reach those in the same way:
```
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.104 -c1
PING 10.0.0.104 (10.0.0.104) 56(84) bytes of data.
64 bytes from 10.0.0.104: icmp_seq=1 ttl=64 time=4.39 ms

--- 10.0.0.104 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 4.391/4.391/4.391/0.000 ms
```

If we disable the proxy service for the mac-vrf, the route is withdrawn:
```
/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 vxlan-agent admin-state disable
commit stay
```

```
A:srl1# /show network-instance default protocols bgp neighbor 1.1.1.4 received-routes evpn                                                                                                                         
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Peer        : 1.1.1.4, remote AS: 65000, local AS: 65000
Type        : static
Description : Local EVPN proxy agent for static VXLAN
Group       : vxlan-agent
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Status codes: u=used, *=valid, >=best, x=stale
Origin codes: i=IGP, e=EGP, ?=incomplete
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
0 Ethernet Auto-Discovery routes 0 used, 0 valid
0 MAC-IP Advertisement routes 0 used, 0 valid
0 Inclusive Multicast Ethernet Tag routes 0 used, 0 valid
0 Ethernet Segment routes 0 used, 0 valid
0 IP Prefix routes 0 used, 0 valid
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--{ + candidate shared default }--[ network-instance mac-vrf-evi10 protocols bgp-evpn ]--
```

...and the service no longer works:
```
jeroen@bembox:~/srlinux/srl-evpn-proxy$ docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c1
PING 10.0.0.103 (10.0.0.103) 56(84) bytes of data.

--- 10.0.0.103 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
```

## Model driven provisioning benefits
The configuration for the agent is fully integrated with the SR Linux system. The agent [YANG model](https://github.com/jbemmel/srl-evpn-proxy/blob/main/src/evpn-proxy-agent/models/srl-evpn-proxy-agent.yang) defines the parameters and constraints that apply. This ensures that - for example - operators can only provision the correct EVI and VNI values for a given mac-vrf service:

```
A:srl1# /network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 vxlan-agent                                                                                                                              
--{ + candidate shared default }--[ network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 vxlan-agent ]--                                                                                               
A:srl1# info                                                                                                                                                                                                       
    admin-state disable
    evi 57069
    vni 11189196
    static-vxlan-remoteips [
        1.1.1.1
    ]
--{ + candidate shared default }--[ network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 vxlan-agent ]--                                                                                               
A:srl1# evi 1234                                                                                                                                                                                                   
--{ +* candidate shared default }--[ network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 vxlan-agent ]--                                                                                              
A:srl1# vni 5678                                                                                                                                                                                                   
--{ +* candidate shared default }--[ network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1 vxlan-agent ]--                                                                                              
A:srl1# commit stay                                                                                                                                                                                                
Error: Error in path: .network-instance{.name=="mac-vrf-evi10"}.protocols.bgp-evpn.bgp-instance{.id==1}.vxlan-agent.evi
    [FailedPrecondition] EVI must match bgp-evpn config
Error in path: .network-instance{.name=="mac-vrf-evi10"}.protocols.bgp-evpn.bgp-instance{.id==1}.vxlan-agent.vni
    [FailedPrecondition] VNI must match ingress vni on the vxlan-interface
```
