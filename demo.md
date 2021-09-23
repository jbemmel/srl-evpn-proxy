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

H1 (on Cumulus1) can ping H2 (on Cumulus2) and H3(on SRL1) can ping H4(on SRL2), but no other flows work.
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
```


