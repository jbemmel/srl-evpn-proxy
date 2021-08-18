import eventlet

# BGPSpeaker needs sockets patched
eventlet.monkey_patch()

# initialize a log handler
# this is not strictly necessary but useful if you get messages like:
#    No handlers could be found for logger "ryu.lib.hub"
import logging
import sys
log = logging.getLogger()
log.addHandler(logging.StreamHandler(sys.stderr))

from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker, EVPN_MULTICAST_ETAG_ROUTE, RF_L2_EVPN

def dump_remote_best_path_change(event):
    print( 'the best path changed:', event.remote_as, event.prefix, event.nexthop, event.is_withdraw )

def detect_peer_down(remote_ip, remote_as):
    print( f'Peer down: {remote_ip} {remote_as}' )

if __name__ == "__main__":
    # need to create socket on localhost on a non-default port, not port 179
    speaker = BGPSpeaker(bgp_server_port=1179, as_number=65000, router_id='10.0.0.1',
                         best_path_change_handler=dump_remote_best_path_change,
                         peer_down_handler=detect_peer_down)

    speaker.vrf_add(route_dist='65000:10',
                    import_rts=['65000:10'],
                    export_rts=['65000:10'],
                    route_family=RF_L2_EVPN)

    speaker.evpn_prefix_add(
        route_type=EVPN_MULTICAST_ETAG_ROUTE,
        route_dist='65000:10',
        esi=0,
        ethernet_tag_id=0,
        # mac_addr=mac_addr,
        # ip_addr=ip_addr,
        next_hop='1.1.1.2', # on behalf of Cumulus
    )

    speaker.neighbor_add('127.0.0.1', 65000) # iBGP with SRL
    count = 1
    while True:
        eventlet.sleep(30)

        speaker.evpn_prefix_add(
                route_type=EVPN_MULTICAST_ETAG_ROUTE,
                route_dist='65000:10',
                esi=0,
                ethernet_tag_id=0,
                mac_addr=f'00:11:22:33:44:0{count}',
                ip_addr=f'10.0.0.{count}/32',
                next_hop='1.1.1.2', # on behalf of Cumulus
        )

        count += 1
        if count == 4:
            speaker.shutdown()
            break
