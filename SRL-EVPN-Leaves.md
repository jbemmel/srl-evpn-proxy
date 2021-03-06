# Basic L2 VXLAN configuration for a pair of leaves with iBGP EVPN

The snippets below can be used to configure a pair of SR Linux nodes with basic underlay connectivity and BGP EVPN between 2 leaves:

For leaf1:
```
enter candidate
/system !!! 1
commit stay
```
For leaf2:
```
enter candidate
/system !!! 2
commit stay
```

Underlay:
```
/delete interface ethernet-1/1
/interface ethernet-1/1
    admin-state enable
    vlan-tagging false
    subinterface 0 {
        description "Basic L3 underlay connection to Leaf${/system!!!| 1 if _=='2' else 2 }"
        type routed
        admin-state enable
        ipv4 { 
          address 192.168.0.${/system!!!|int(_) - 1}/31
          exit
        }
        ipv6 { 
          address 2001::192:168:0:${/system!!!|int(_) - 1}/127
          exit
        }
    }

/delete interface lo0
/interface lo0
    description "Loopback"
    admin-state enable
    subinterface 0 {
        admin-state enable
        ipv4 { 
          address 1.1.1.${/system!!!}/32
          exit
        }
        ipv6 { 
          address 2001::1:1:1:${/system!!!}/128
          exit
        }
    }
/delete network-instance default
/network-instance default
type default
admin-state enable
interface ethernet-1/1.0 { }
commit stay
```

BGP IPv4 (for loopbacks) + EVPN, with static neighbor peering on the interface
```
/routing-policy
policy accept-all {
   default-action { accept { } }
}
/network-instance default
delete protocols bgp
protocols bgp {
        admin-state enable
        router-id 1.1.1.${/system!!!}
        autonomous-system 65000
        export-policy accept-all
        group leaves {
            admin-state enable
            peer-as 65000
            ipv4-unicast { admin-state enable }
            ipv6-unicast { admin-state disable }
            evpn { admin-state enable }
        }
        neighbor 192.168.0.${/system!!!| 1 if _=='1' else 0 } {
          admin-state enable
          peer-group leaves
        }
    }
commit stay
```

Check BGP peering:
```
/show network-instance default protocols bgp neighbor
```

VXLAN system interface, added to default network-instance:
```
/interface system0
admin-state enable
subinterface 0 {
  admin-state enable
  ipv4 { 
    address 1.1.1.${/system!!!}/32
    exit
  }
}
/network-instance default
interface system0.0 { }
commit stay
```

Basic L2 Ethernet VPN service:
```
/tunnel-interface vxlan0
vxlan-interface 1 {
        type bridged
        ingress {
            vni 10
        }
        egress {
            source-ip use-system-ipv4-address
        }
    }
 
/interface irb0
admin-state enable
subinterface 1 {
    admin-state enable
    ipv4 {
        address 10.10.10.${/system!!!}/24
           primary
           exit
    }
    ipv6 {
    }
}

/network-instance mac-vrf-evi10
    type mac-vrf
    admin-state enable
    interface irb0.1 { }
    vxlan-interface vxlan0.1 { }
    protocols {
        bgp-evpn {
            bgp-instance 1 {
                admin-state enable
                vxlan-interface vxlan0.1
                evi 10
                ecmp 8
            }
        }
        bgp-vpn {
          bgp-instance 1 { }
        }
    }

/network-instance ip-vrf
type ip-vrf
admin-state enable
interface irb0.1 { }
commit stay
```
