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

