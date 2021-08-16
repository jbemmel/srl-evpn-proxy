# Basic underlay configuration for a pair of leaves with iBGP EVPN

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

Leaf1:
```
/delete interface ethernet-1/1
/interface ethernet-1/1
    description "Basic underlay connection to Leaf${/system!!!| 1 if _=='2' else 2 }"
    admin-state enable
    subinterface 0 {
        type routed
        admin-state enable
        ipv4 { address 192.168.0.${/system!!!|int(_) - 1}/31 { } }
        ipv6 { address 2001::192:168:0:${/system!!!|int(_) - 1}/127 { } }
    }
/delete interface lo0
/interface lo0
    description "Loopback"
    admin-state enable
    subinterface 0 {
        admin-state enable
        ipv4 { address 1.1.1.${/system!!!}/32 { } }
        ipv6 { address 2001::1:1:1:${/system!!!}/128 { } }
    }
/delete network-instance default
/network-instance default
type default
admin-state enable
interface lo0.0 { }
interface ethernet-1/1.0 { }
commit stay
```

Using BGP as IGP, with static neighbor peering on the interface (ipv4):
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
        }
        neighbor 192.168.0.${/system!!!| 1 if _=='2' else 2 } {
          admin-state enable
          peer-group leaves
        }
    }
commit now
```

Check BGP peering:
```
/show network-instance default protocols bgp neighbor
```
