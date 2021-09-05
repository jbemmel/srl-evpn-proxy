import eventlet

# BGPSpeaker needs sockets patched -> breaks SRL registration if done too late
# eventlet.monkey_patch( socket=True, select=True ) # adding only ( socket=True ) allows SRL, but then BGP doesn't work :(
eventlet.monkey_patch() # need thread too

# Google core libraries don't support eventlet; workaround
import grpc
from grpc.experimental import eventlet as grpc_eventlet

grpc_eventlet.init_eventlet() # Fix gRPC eventlet interworking, early

from ryu.services.protocols.bgp.bgpspeaker import (BGPSpeaker,
                                                  EVPN_MULTICAST_ETAG_ROUTE,
                                                  EVPN_MAC_IP_ADV_ROUTE,
                                                  RF_L2_EVPN,
                                                  PMSI_TYPE_INGRESS_REP)

class EVPNProxy(object):

 def __init__(self,loopback="127.0.0.1",as_number=65000):
  logging.info( "Starting new EVPN Proxy instance..." )
  self.vni_2_macvrf = {}

  # BGP properties used in multiple places
  self.loopback = loopback
  self.as_number = as_number

 def connectBGP_EVPN(self,peer,local_bgp_port=1179,remote_bgp_port=179,connect_mode='active',local_pref=100):

  def best_path_change_event(event):
    logging.warning( f'Best path changed: {event}' )

  def peer_up_handler(router_id, remote_as):
    logging.warning( f'Peer UP: {router_id} {remote_as}' )
  def peer_down_handler(router_id, remote_as):
    logging.warning( f'Peer DOWN: {router_id} {remote_as}' )

  self.bgpSpeaker = BGPSpeaker(bgp_server_hosts=[self.loopback],
                               bgp_server_port=local_bgp_port,
                               as_number=self.as_number,
                               local_pref=local_pref,
                               router_id=self.loopback,
                               best_path_change_handler=best_path_change_event,
                               peer_up_handler=peer_up_handler,
                               peer_down_handler=peer_down_handler)

  # Start iBGP EVPN peering
  self.bgpSpeaker.neighbor_add( peer,
                                remote_as=self.as_number,
                                local_as=self.as_number,
                                enable_ipv4=False, enable_evpn=True,
                                connect_mode=connect_mode)
  return self

 def shutdown(self):
   self.bgpSpeaker.shutdown()

 #
 # Network events
 #
 def rxVXLAN_ARP( self, vni, mac, vtep ):
  pass

 def rxEVPN_RT2( self, vni, mac, vtep ):
  pass

 def checkAdvertisedRoute( self, vni, mac ):
    # lookup MAC in vni table
    if vni in self.vni_2_macvrf:
        macvrf = self.vni_2_macvrf[ vni ]
        return macvrf[mac]['vtep'] if mac in macvrf else None
    logging.debug( f"No route advertised for MAC {mac} in VNI {vni}" )
    return None
