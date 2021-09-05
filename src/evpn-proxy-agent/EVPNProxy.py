import eventlet

# BGPSpeaker needs sockets patched -> breaks SRL registration if done too late
# eventlet.monkey_patch( socket=True, select=True ) # adding only ( socket=True ) allows SRL, but then BGP doesn't work :(
eventlet.monkey_patch() # need thread too

# Google core libraries don't support eventlet; workaround
#import grpc
#from grpc.experimental import eventlet as grpc_eventlet
#grpc_eventlet.init_eventlet() # Fix gRPC eventlet interworking, early

import logging

from ryu.services.protocols.bgp.bgpspeaker import (BGPSpeaker,
                                                  EVPN_MULTICAST_ETAG_ROUTE,
                                                  EVPN_MAC_IP_ADV_ROUTE,
                                                  RF_L2_EVPN,
                                                  PMSI_TYPE_INGRESS_REP)

class EVPNProxy(object):

 def __init__(self,router_id,vnis='*',as_number=65000,learn_vteps=True):
   logging.info( "Starting new EVPN Proxy instance..." )

   # BGP properties used in multiple places
   self.router_id = router_id
   self.as_number = as_number
   self.learn_vteps = learn_vteps  # Whether to add static VTEPs when seen

   self.vnis = vnis     # Enabled VNIs, default '*'=all
   self.evpn_vteps = {} # Discovered set of EVPN VTEPs
   self.vni_2_evi = {}  # Mapping of VNI(24-bit)->EVI(16 bit)
   self.vni_2_macvrf = {}
   self.bgp_vrfs = {}

 def connectBGP_EVPN(self,local_bgp_port=1179,local_pref=100):
   """ Connects to BGP peer to receive EVPN route updates """

   def best_path_change_event(event):
     logging.warning( f'Best path changed: {event}' )

   def peer_up_handler(router_id, remote_as):
     logging.warning( f'Peer UP: {router_id} {remote_as}' )
   def peer_down_handler(router_id, remote_as):
     logging.warning( f'Peer DOWN: {router_id} {remote_as}' )

   self.bgpSpeaker = BGPSpeaker(bgp_server_hosts=[self.router_id],
                               bgp_server_port=local_bgp_port,
                               as_number=self.as_number,
                               local_pref=local_pref,
                               router_id=self.router_id,
                               best_path_change_handler=best_path_change_event,
                               peer_up_handler=peer_up_handler,
                               peer_down_handler=peer_down_handler)

   # Start iBGP EVPN peering
   self.bgpSpeaker.neighbor_add( self.router_id,
                                remote_as=self.as_number,
                                local_as=self.as_number,
                                enable_ipv4=False, enable_evpn=True,
                                connect_mode='active')
   return self

 def shutdown(self):
   if self.bgpSpeaker is not None:
      self.bgpSpeaker.shutdown()
      self.bgpSpeaker = None

 def addStaticVTEP( self, vni : int, evi : int, vtep_ip : str ):
    # Update VNI->EVI mapping, TODO should be consistent
    self.vni_2_evi[ vni ] = evi
    return self._addStaticVTEP(vni, evi, vtep_ip )

 def _addStaticVTEP( self, vni : int, evi : int, vtep_ip : str ):
     """
     Adds a static VTEP to the configuration and announces a multicast route
     to EVPN peer

     vni: Virtual Network Identifier from VXLAN
     evi: Ethernet Virtual Instance (used for auto-generated RT/RD)
     vtep_ip: IPv4 address of static VTEP to proxy for
     """
     rd = f"{vtep_ip}:{evi}"
     rt = f"{self.as_number}:{evi}"
     logging.info(f"addStaticVTEP: Adding VRF...RD={rd} RT={rt}")
     self.bgpSpeaker.vrf_add(route_dist=rd,import_rts=[rt],export_rts=[rt],route_family=RF_L2_EVPN)
     logging.info("Adding EVPN multicast route...")
     #
     # For RD use the static VTEP's IP, just like it would do if it was
     # EVPN enabled itself. That way, any proxy will announce the same
     # route
     #
     self.bgpSpeaker.evpn_prefix_add(
         route_type=EVPN_MULTICAST_ETAG_ROUTE,
         route_dist=rd,
         # esi=0, # should be ignored
         ethernet_tag_id=0,
         # mac_addr='00:11:22:33:44:55', # not relevant for MC route
         ip_addr=self.router_id, # originator == proxy IP
         tunnel_type='vxlan',
         vni=vni, # Not sent in advertisement
         gw_ip_addr=vtep_ip,
         next_hop=vtep_ip, # on behalf of remote VTEP
         pmsi_tunnel_type=PMSI_TYPE_INGRESS_REP,
         # Added via patch
         tunnel_endpoint_ip=vtep_ip
     )
     self.bgp_vrfs[ rd ] = vni
     return rd

 def announceEVPNRoute( self, rd: str, vni: int, mac: str, static_vtep: str,
                        mobility_seq: int, ip=None ):
    self.bgpSpeaker.evpn_prefix_add(
      route_type=EVPN_MAC_IP_ADV_ROUTE, # RT2
      route_dist=rd,
      esi=0, # Single homed
      ethernet_tag_id=0,
      mac_addr=mac,
      ip_addr=ip, # SRL peers are L2 only, ignoring this IP
      next_hop=static_vtep, # on behalf of remote VTEP
      tunnel_type='vxlan',
      vni=vni,
      gw_ip_addr=static_vtep,
      mac_mobility=mobility_seq # Sequence number for MAC mobility
    )

 def withdrawEVPNRoute( self, rd: str, mac: str, ip=None ):
    self.bgpSpeaker.evpn_prefix_del(
      route_type=EVPN_MAC_IP_ADV_ROUTE, # RT2
      route_dist=rd, # original RD
      # vni=vni, # not used/allowed in withdraw
      ethernet_tag_id=0,
      mac_addr=mac,
      ip_addr=ip
    )

 #
 # Network events
 #
 def rxVXLAN_ARP( self, vni, vtep_src, vtep_dst, mac ):
   if self.vnis=='*' or vni in self.vnis:
      # Check if src or dst is from an EVPN VTEP
      if vtep_src in self.evpn_vteps:
         logging.info( f"ARP from EVPN VTEP {vtep_src} -> ignoring" )
      elif vtep_dst in self.evpn_vteps:
         logging.info( f"ARP from static VTEP: {vtep_src}" )
         return self.rxVXLAN_ARP_from_static_VTEP(vni,vtep_src,mac)
      else:
         logging.info( f"ARP packet:neither src={vtep_src} nor dst={vtep_dst} is EVPN vtep? {self.evpn_vteps}" )
   else:
       logging.warning( f"rxVXLAN_ARP: VNI {vni} not enabled, ignoring {mac} on {vtep_src}->{vtep_dst}" )
   return False # Ignored

 def rxVXLAN_ARP_from_static_VTEP( self, vni, static_vtep, mac ):
     """
     Process ARP received from static VTEP to send EVPN MAC route (RT2)
     """

     if vni not in self.vni_2_evi:
         logging.error( f"VNI({vni}): EVI mapping unknown" )
         return False
     evi = self.vni_2_evi[vni]

     # For RD, use the static VTEP's IP, just as would happen when it would
     # advertise the routes itself. This implies we need to create a VRF
     # per static VTEP locally
     rd = f"{static_vtep}:{evi}"

     if rd not in self.bgp_vrfs and self.learn_vteps:
         self._addStaticVTEP( vni, evi, static_vtep )

     mac_vrf = self.vni_2_macvrf[ vni ] if vni in self.vni_2_macvrf else {}
     mobility_seq = None # First time: no attribute

     if mac in mac_vrf:
         cur = mac_vrf[ mac ]
         logging.info( f"MAC {mac} already announced: {cur}, checking for MAC move" )
         if cur['vtep'] == static_vtep:
            logging.info( f"VNI {vni}: MAC {mac} already announced with VTEP {static_vtep}" )

            # if cur['ip'] == ip:
            #   return False
            # logging.info( f"IP change detected for MAC {mac}")
            return False

         mobility_seq = cur['seq'] + 1
         if cur['vtep'] != "tbd":
            logging.info( f"MAC move - VTEP changed to {cur['vtep']}, withdrawing my route" )
            self.withdrawEVPNRoute( f"{cur['vtep']}:{evi}", mac )
         else:
            logging.info( f"EVPN route for {mac} already withdrawn triggered by other EVPN proxy route" )

         # Could add a timestamp (last seen) + aging
         logging.info( f"VNI {vni}: MAC {mac} moved to {static_vtep} new mobility_seq={mobility_seq}" )

         # Could track 'ip' here too, but complicates the number of corner cases
         cur.update( { 'vtep' : static_vtep, 'seq' : mobility_seq } )
     else:
         logging.info( f"VNI {vni}: MAC {mac} never seen before, associating with VTEP {static_vtep}" )
         mac_vrf.update( { mac : { 'vtep': static_vtep, 'seq': -1 } } )

     self.vni_2_macvrf[ vni ] = mac_vrf
     logging.info( f"Announcing EVPN MAC route...evpn_vteps={self.evpn_vteps}" )
     self.announceEVPNRoute( rd, vni, mac, static_vtep, mobility_seq )
     return True

 def rxEVPN_RT2( self, vni, mac, vtep ):
  pass

 def checkAdvertisedRoute( self, vni, mac ):
    # lookup MAC in vni table
    if vni in self.vni_2_macvrf:
        macvrf = self.vni_2_macvrf[ vni ]
        return macvrf[mac]['vtep'] if mac in macvrf else None
    logging.debug( f"No route advertised for MAC {mac} in VNI {vni}" )
    return None

 def isEVPNPeer( self, vtep: str ):
    return vtep in self.evpn_vteps
