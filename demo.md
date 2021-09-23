# VXLAN Agent demo scenario
![plot](images/EVPN_proxy_lab_with_spine.png)
## Installation
```
bash -c "$(curl -sL https://get-clab.srlinux.dev)" # install Containerlab, version 0.18 or higher
git clone & make https://github.com/jbemmel/srl-baseimage
make # to build the custom 'srl/evpn-proxy-agent' Docker container
cd labs/spine-leaf && sudo containerlab deploy -t static-vxlan-with-spine.lab
```

This results in a setup containing 2 Cumulus nodes with static VXLAN configuration, and 2 SR Linux nodes with dynamic EVPN VXLAN.

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
