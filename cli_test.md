# A collection of CLI snippets to test configuration changes

Given a model-driven system, test cases like these could be automatically generated: For every leaf node in the model, generate a test case to add it, to change it, to remove it, etc.
As a starting point, the cases below were hand-crafted.

## Change VNI
The VNI must match the VXLAN ingress VNI
```
enter candidate
/tunnel-interface vxlan0
vxlan-interface 0
ingress vni 1234
/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1
vxlan-agent
vni ${/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/ingress/vni}
commit stay
```

### Validation
```
info from state /network-instance default bgp-rib attr-sets attr-set rib-in index ${//network-instance[name=default]/bgp-rib/evpn/rib-in-out/rib-in-pre/imet-routes[originating-router=1.1.1.4]/attr_id}
```

## Change EVI
The EVI must match the bgp-evpn config of the encompassing mac-vrf
```
enter candidate
/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1
evi 1234
vxlan-agent
evi ${/network-instance[name=mac-vrf-evi10]/protocols/bgp-evpn/bgp-instance[id=1]/evi}
commit stay
```

### Validation
The Route Distinguishers for all VTEPs should include the updated EVI value
```
show /network-instance default protocols bgp neighbor 1.1.1.4 received-routes evpn
```

## Remove and add back static VTEP
```
/network-instance mac-vrf-evi10 protocols bgp-evpn bgp-instance 1
vxlan-agent
delete static-vtep 1.1.1.1
commit stay
```
and add it back, without MACs:
```
static-vtep 1.1.1.1
commit stay
```

# Model-driven testing
gNMIc can auto-generate test cases:
```
gnmic generate --file /opt/demo-agents/srl-evpn-proxy-agent/models/srl-evpn-proxy-agent.yang set-request --dir /opt/srlinux/models/ \
 --update /network-instance[name=mac-vrf-evi10]/protocols/bgp-evpn/bgp-instance[id=1]/vxlan-agent
```
