import eventlet
import signal

# BGPSpeaker needs sockets patched
eventlet.monkey_patch()

# initialize a log handler
# this is not strictly necessary but useful if you get messages like:
#    No handlers could be found for logger "ryu.lib.hub"
import logging
import sys
log = logging.getLogger()
log.addHandler(logging.StreamHandler(sys.stderr))

from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker,
                                                  EVPN_MULTICAST_ETAG_ROUTE,
                                                  EVPN_MAC_IP_ADV_ROUTE,
                                                  RF_L2_EVPN,
                                                  PMSI_TYPE_INGRESS_REP

def dump_remote_best_path_change(event):
    print( 'the best path changed:', event.remote_as, event.prefix, event.nexthop, event.is_withdraw )

def detect_peer_down(remote_ip, remote_as):
    print( f'Peer down: {remote_ip} {remote_as}' )

if __name__ == "__main__":

    LOCAL_LOOPBACK = "1.1.1.4" # Local loopback interface on SRL
    VTEP_LOOPBACK = "1.1.1.2"  # Remote VTEP we're impersonating
    AS = 65000
    VNI = 10

    # need to create socket on localhost on a non-default port, not port 179
    # Need to connect from loopback IP
    # Router ID is used as tunnel endpoint in BGP UPDATEs
    speaker = BGPSpeaker(bgp_server_hosts=[LOCAL_LOOPBACK], bgp_server_port=1179,
                         as_number=AS, router_id=VTEP_LOOPBACK,
                         best_path_change_handler=dump_remote_best_path_change,
                         peer_down_handler=detect_peer_down)

    rd = f'{AS}:{VNI}'
    speaker.vrf_add(route_dist=rd,import_rts=[rd],export_rts=[rd],route_family=RF_L2_EVPN)

    speaker.evpn_prefix_add(
        route_type=EVPN_MULTICAST_ETAG_ROUTE,
        route_dist=rd,
        # esi=0, # should be ignored
        ethernet_tag_id=0,
        # mac_addr='00:11:22:33:44:55', # not relevant?
        ip_addr=VTEP_LOOPBACK, # origin
        tunnel_type='vxlan',
        vni=VNI,
        gw_ip_addr=VTEP_LOOPBACK,
        next_hop=VTEP_LOOPBACK, # on behalf of remote VTEP
        pmsi_tunnel_type=PMSI_TYPE_INGRESS_REP
    )

    print( "Adding SRL neighbor..." )
    # TODO enable_four_octet_as_number=True, enable_enhanced_refresh=True
    speaker.neighbor_add(LOCAL_LOOPBACK, AS, enable_ipv4=False, enable_evpn=True, connect_mode='active') # iBGP with SRL

    print( "Adding new EVPN RT2 route..." )
    speaker.evpn_prefix_add(
        route_type=EVPN_MAC_IP_ADV_ROUTE, # RT2
        route_dist=rd,
        esi=0,
        ethernet_tag_id=0,
        mac_addr='00:11:22:33:44:55',
        ip_addr='10.0.0.123',
        next_hop=VTEP_LOOPBACK, # on behalf of remote VTEP
        tunnel_type='vxlan',
        vni=VNI,
        gw_ip_addr=VTEP_LOOPBACK,
        next_hop=VTEP_LOOPBACK, # on behalf of remote VTEP
    )

    def handler(signum, frame):
       print( f"\nShutting down BGP instance...signal={signum}" )
       speaker.neighbor_del(LOCAL_LOOPBACK)
       speaker.shutdown()
       system.exit(0)

    # Register our handler for keyboard interrupt and termination signals
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    # The process main thread does nothing but waiting for signals
    print( "Pausing for interrupts..." )
    signal.pause()
