set /system gnmi-server unix-socket admin-state enable
set /auto-config-agent gateway ipv4 10.0.0.1/24 location leaf
set /auto-config-agent lacp active # reload-delay-secs 0

# l2-only-leaves still troublesome, port towards spine becomes mc-lag
# set /auto-config-agent base-as 65100
set /auto-config-agent igp bgp-unnumbered evpn model symmetric-irb auto-lags disabled bgp-peering ipv4 overlay-as 65000 route-reflector spine

# Test ipv6 underlay
# set /auto-config-agent evpn ipv6-nexthops true

# NEW: Service config
set /auto-config-agent service 1 name "Boot" vlan 0 l3 gateway anycast-gw-on-leaves gateway-ipv4 10.0.0.1/24

# Test DHCP tracing - not working
set /interface mgmt0 subinterface 0 ipv4 dhcp-client trace-options trace [messages]
