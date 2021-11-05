#!/usr/bin/env python
# coding=utf-8

import eventlet

# BGPSpeaker needs sockets patched -> breaks SRL registration if done too late
# eventlet.monkey_patch( socket=True, select=True ) # adding only ( socket=True ) allows SRL, but then BGP doesn't work :(
eventlet.monkey_patch() # need thread too

# Google core libraries don't support eventlet; workaround
import grpc
from grpc.experimental import eventlet as grpc_eventlet

grpc_eventlet.init_eventlet() # Fix gRPC eventlet interworking, early

# May need to start a separate Python process for BGP

from datetime import datetime, timezone, timedelta
import time
import sys
import logging
import socket
import os
import re
import struct
import ipaddress
import json
import traceback
import subprocess
from threading import Timer
import pwd

# sys.path.append('/usr/lib/python3.6/site-packages/sdk_protos')
import sdk_service_pb2
import sdk_service_pb2_grpc
import lldp_service_pb2
import config_service_pb2
import sdk_common_pb2

# Local gNMI connection
from pygnmi.client import gNMIclient, telemetryParser

# To report state back
import telemetry_service_pb2
import telemetry_service_pb2_grpc

from logging.handlers import RotatingFileHandler

#
# BGP imports
#
import netns
import signal
from ryu.services.protocols.bgp.bgpspeaker import (BGPSpeaker,
                                                  EVPN_MULTICAST_ETAG_ROUTE,
                                                  EVPN_MAC_IP_ADV_ROUTE,
                                                  RF_L2_EVPN,
                                                  PMSI_TYPE_INGRESS_REP)

from ryu.lib.packet.bgp import (EvpnNLRI, BGPEvpnMacMobilityExtendedCommunity,
                                BGP_ATTR_TYPE_ORIGINATOR_ID,
                                BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)

# Ryu has its own threading model
from ryu.lib import hub

############################################################
## Agent will start with this name
############################################################
agent_name='static_vxlan_agent'

############################################################
## Open a GRPC channel to connect to sdk_mgr on the dut
## sdk_mgr will be listening on 50053
############################################################
#channel = grpc.insecure_channel('unix:///opt/srlinux/var/run/sr_sdk_service_manager:50053')
channel = grpc.insecure_channel('127.0.0.1:50053')
metadata = [('agent_name', agent_name)]
stub = sdk_service_pb2_grpc.SdkMgrServiceStub(channel)

# Try global gNMI connection
#gnmi = gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
#                  username="admin",password="admin",
#                  insecure=True, debug=False)
#gnmi.connect()

############################################################
## Subscribe to required event
## This proc handles subscription of: Interface, LLDP,
##                      Route, Network Instance, Config
############################################################
def Subscribe(stream_id, option):
    # XXX Does not pass pylint
    op = sdk_service_pb2.NotificationRegisterRequest.AddSubscription
    if option == 'cfg':
        entry = config_service_pb2.ConfigSubscriptionRequest()
        # entry.key.js_path = '.' + agent_name
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, config=entry)

    subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    logging.info( f'Status of subscription response for {option}:: {subscription_response.status}' )

############################################################
## Subscribe to all the events that Agent needs
############################################################
def Subscribe_Notifications(stream_id):
    '''
    Agent will receive notifications to what is subscribed here.
    '''
    if not stream_id:
        logging.info("Stream ID not sent.")
        return False

    # Subscribe to config changes, first
    Subscribe(stream_id, 'cfg')

def Add_Telemetry( path_obj_list ):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_update_request = telemetry_service_pb2.TelemetryUpdateRequest()
    for js_path,obj in path_obj_list:
      telemetry_info = telemetry_update_request.state.add()
      telemetry_info.key.js_path = js_path
      telemetry_info.data.json_content = json.dumps(obj)
    logging.info(f"Telemetry_Update_Request :: {telemetry_update_request}")
    telemetry_response = telemetry_stub.TelemetryAddOrUpdate(request=telemetry_update_request, metadata=metadata)
    return telemetry_response

def Remove_Telemetry(js_paths):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_del_request = telemetry_service_pb2.TelemetryDeleteRequest()
    for path in js_paths:
      telemetry_key = telemetry_del_request.key.add()
      telemetry_key.js_path = path
    logging.info(f"Telemetry_Delete_Request :: {telemetry_del_request}")
    telemetry_response = telemetry_stub.TelemetryDelete(request=telemetry_del_request, metadata=metadata)
    return telemetry_response

def AnnounceMulticastRoute( state, rd, vtep_ip, vni ):
   state.speaker.evpn_prefix_add(
       route_type=EVPN_MULTICAST_ETAG_ROUTE,
       route_dist=rd,
       # esi=0, # should be ignored
       ethernet_tag_id=0,
       # mac_addr='00:11:22:33:44:55', # not relevant for MC route
       ip_addr=state.params['source_address'], # originator == proxy IP
       tunnel_type='vxlan',
       vni=vni, # Sent as label
       gw_ip_addr=vtep_ip,
       next_hop=vtep_ip, # on behalf of remote VTEP
       pmsi_tunnel_type=PMSI_TYPE_INGRESS_REP,
       # Added via patch
       tunnel_endpoint_ip=vtep_ip
)

def WithdrawMulticastRoute( state, rd, vtep_ip ):
    try:
       state.speaker.evpn_prefix_del(
         route_type=EVPN_MULTICAST_ETAG_ROUTE, # RT3
         route_dist=rd, # original RD
         # vni=mac_vrf['vni'], # not used/allowed in withdraw
         ethernet_tag_id=0
       )
    except Exception as ex:
       logging.error( ex )

def AnnounceRoute( state, mac_vrf, vtep_ip, mac, ip, mobility_seq ):
   state.speaker.evpn_prefix_add(
       route_type=EVPN_MAC_IP_ADV_ROUTE, # RT2
       route_dist=AutoRouteDistinguisher(vtep_ip,mac_vrf),
       esi=0, # Single homed
       ethernet_tag_id=0,
       mac_addr=mac,
       ip_addr=ip if state.params['include_ip'] else None, # Enables remote peers to perform proxy ARP
       next_hop=vtep_ip, # on behalf of remote VTEP
       tunnel_type='vxlan',
       vni=mac_vrf['vni'],
       gw_ip_addr=vtep_ip,
       mac_mobility=mobility_seq # Sequence number for MAC mobility
   )

def WithdrawRoute( state, mac_vrf, vtep_ip, mac, ip=None ):
    try:
       state.speaker.evpn_prefix_del(
        route_type=EVPN_MAC_IP_ADV_ROUTE, # RT2
        route_dist=AutoRouteDistinguisher(vtep_ip,mac_vrf), # original RD
        # vni=mac_vrf['vni'], # not used/allowed in withdraw
        ethernet_tag_id=0,
        mac_addr=mac,
        ip_addr=ip if state.params['include_ip'] else None
       )
    except Exception as ex:
       logging.error( ex )

    # Also remove telemetry
    js_path = f'.vxlan_proxy.static_vtep{{.vtep_ip=="{vtep_ip}"}}.mac_vrf{{.name=="{mac_vrf["name"]}"}}.mac{{.address=="{mac}"}}'
    Remove_Telemetry( [js_path] )

def UpdateMACVRF( state, mac_vrf, new_vni=None, new_evi=None ):
   logging.info( f"UpdateMACVRF mac_vrf={mac_vrf} new_vni={new_vni} new_evi={new_evi}" )

   if new_evi:
      # Clean up old VTEPs, RDs need to be changed
      for static_vtep in list( mac_vrf['vxlan_vteps'].keys() ):
         Remove_Static_VTEP( state, mac_vrf, static_vtep, clear_macs=False )
      mac_vrf['evi'] = new_evi

   if new_vni:
      # Clean up old EVPN routes, VNI needs to be changed
      for vtep_ip,macs in mac_vrf['vxlan_vteps'].items():
         rd = AutoRouteDistinguisher( vtep_ip, mac_vrf )
         WithdrawMulticastRoute( state, rd, vtep_ip )
         for mac,status in macs.items():
            if status=='static_announced':
               WithdrawRoute( state, mac_vrf, vtep_ip, mac )
               mac_vrf['vxlan_vteps'][ vtep_ip ][ mac ] = 'static'
      mac_vrf['vni'] = new_vni

   # Make sure all VTEPs exist
   if mac_vrf['admin_state'] == "enable":
     for vtep_ip,macs in mac_vrf['vxlan_vteps'].items():
       Add_Static_VTEP( state, mac_vrf, vtep_ip )
       for mac,status in macs.items():
           if status != 'static_announced' or new_evi:
               AnnounceRoute( state, mac_vrf, vtep_ip, mac, ip=None, mobility_seq=-1 )
               mac_vrf['vxlan_vteps'][ vtep_ip ][ mac ] = 'static_announced'

   else:
     logging.info( "UpdateMACVRF: admin-state not 'enable'" )

# Updates a single static VTEP
def UpdateMACVRF_StaticVTEP( state, mac_vrf, vtep_ip, macs ):
   logging.info( f"UpdateMACVRF_StaticVTEP mac_vrf={mac_vrf} vtep_ip={vtep_ip} macs={macs}" )

   vteps = mac_vrf['vxlan_vteps']
   vtep = vteps[ vtep_ip ] if vtep_ip in vteps else None

   if hasattr( state, 'speaker' ):  # BGP running?
      if vtep:
         # Clean up old MAC routes
         macs_to_keep = list( macs.keys() )
         for mac in vtep.keys():
            if mac not in macs_to_keep:
               WithdrawRoute( state, mac_vrf, vtep_ip, mac )
      else:
         Add_Static_VTEP( state, mac_vrf, vtep_ip )

      # Announce new MACs
      for mac in macs.keys():
          if not vtep or mac not in vtep or vtep[mac] != 'static_announced':
              AnnounceRoute( state, mac_vrf, vtep_ip, mac, ip=None, mobility_seq=-1 )
              macs[ mac ] = 'static_announced'

   vteps[ vtep_ip ] = macs

#
# Runs BGP EVPN as a separate thread>, using Ryu hub
#
#from threading import Thread
#class BGPEVPNThread(Thread):
#   def __init__(self):
#       Thread.__init__(self)

def runBGPThread( state ):
  LOCAL_LOOPBACK = state.params['source_address']
  NEIGHBOR = state.params[ 'peer_address' ]
  if NEIGHBOR=="127.0.0.1": # Connect to 127.0.0.1 does not work
     NEIGHBOR = LOCAL_LOOPBACK

  evpn_vteps = {}

  def best_path_change_handler(event):
    logging.info( f'BGP best path changed: {event.path} prefix={event.prefix} NLRI={event.path.nlri}' )
        # event.remote_as, event.prefix, event.nexthop, event.is_withdraw, event.path )

    try:
      # Could remove VTEP IP upon withdraw too
      if not event.is_withdraw:
         originator_id = event.path.get_pattr(BGP_ATTR_TYPE_ORIGINATOR_ID)
         if event.path.nlri.type == EvpnNLRI.INCLUSIVE_MULTICAST_ETHERNET_TAG:

            # SRL EVPN VTEP does not normally include an 'originator' attribute
            if originator_id and originator_id.value != event.nexthop:
               logging.info( f"Detected another EVPN proxy: {originator_id.value}" )

            else:
               logging.info( f"Multicast route from EVPN VTEP: {event.nexthop}" )
               evpn_vteps[ event.nexthop ] = event.remote_as
               # Could withdraw routes and remove static MACs if this IP matches
               # a static vtep in our configuration
               data = { 'evpn_vteps': sorted(evpn_vteps.keys()) }
               Add_Telemetry( [('.vxlan_proxy', data)] )

         # check for RT2 MAC moves between static VTEPs and EVPN VTEPs
         # event.label is reduced to the 20-bit MPLS label
         elif hasattr( event.path.nlri, 'vni'):
           vni = event.path.nlri.vni
           if vni not in state.mac_vrfs:
               logging.warning( f"BGP: No mac-vrf mapping for VNI: {vni}" )
               return
           mac_vrf = state.mac_vrfs[ vni ]

           logging.info( f"Received EVPN route update for VNI {vni}: {mac_vrf}" )
           mac = event.path.nlri.mac_addr
           if mac in mac_vrf['macs']:
             cur = mac_vrf['macs'][ mac ]
             # Don't bother checking IP; SRL MAC-VRF doesn't send it
             # Only other proxies do
             if cur['vtep'] != event.nexthop and cur['vtep'] != 'tbd':
                 logging.info( f"EVPN MAC-move detected {cur['vtep']} -> {event.nexthop}" )

                 # if this is from an EVPN VTEP, withdraw our route - our job is done
                 if not originator_id or originator_id.value == event.nexthop:
                    logging.info( f"Removing MAC moved to EVPN VTEP {event.nexthop} from EVPN proxy: {mac}" )
                    WithdrawRoute( state, mac_vrf, cur['vtep'], mac, cur['ip'] )
                    del mac_vrf['macs'][ mac ]
                 # else (from other EVPN proxy) only withdraw if VTEP IP changed, but don't remove MAC
                 # as we need to keep track of the mobility sequence number
                 elif originator_id and originator_id.value != event.nexthop:

                    # Check Mobility sequence - route may be stale
                    def GetMACMobility():
                       ext_comms = event.path.get_pattr(BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
                       for c in ext_comms.communities:
                          if isinstance( c, BGPEvpnMacMobilityExtendedCommunity ):
                              return c.sequence_number
                       return -1 # not present

                    if GetMACMobility() < cur['seq']:
                       logging.info( f"Local mobility sequence {cur['seq']} higher than peer - keeping route" )
                       return

                    logging.info( f"Withdrawing MAC {mac} route announced by other EVPN proxy {originator_id.value} with different VTEP: {event.nexthop}" )
                    WithdrawRoute( state, mac_vrf, cur['vtep'], mac, cur['ip'] )
                    cur['vtep'] = "tbd" # Mark as withdrawn
                 else:
                    logging.warning( "TODO: Compare/update mobility sequence number, even if same VTEP nexthop?" )
         else:
           logging.info( "Not multicast and no VNI -> ignoring" )

      # Never remove EVPN VTEP from list, assume once EVPN = always EVPN
    except Exception as ex:
      tb_str = ''.join(traceback.format_tb(ex.__traceback__))
      logging.error( f"Exception in best_path_change_handler: {ex} ~ {tb_str}" )

  def peer_up_handler(router_id, remote_as):
      logging.warning( f'Peer UP: {router_id} {remote_as}' )

  def peer_down_handler(router_id, remote_as):
      logging.warning( f'Peer DOWN: {router_id} {remote_as}' )
  # need to create socket on localhost on a non-default port, not port 179
  # Need to connect from loopback IP, not 127.0.0.x
  # Router ID is used as tunnel endpoint in BGP UPDATEs
  # => Code updated to allow any tunnel endpoint IP

  # Wait for gNMI socket to exist
  # while not os.path.exists('/opt/srlinux/var/run/sr_gnmi_server'):
  #   logging.info("Waiting for gNMI unix socket to be created...")
  #   eventlet.sleep(1)

  # During system startup, wait for netns to be created
  while not os.path.exists('/var/run/netns/srbase-default'):
     logging.info("Waiting for srbase-default netns to be created...")
     eventlet.sleep(1)

  logging.info("Starting BGP thread in srbase-default netns...")
  # Requires root permissions
  # Ryu modified to support net_ns parameter, needed for reconnections
  # with netns.NetNS(nsname="srbase-default"):
  logging.info("Starting BGPSpeaker in netns...")

  state.speaker = BGPSpeaker(bgp_server_hosts=[LOCAL_LOOPBACK],
                             bgp_server_port=1179,
                             net_ns="srbase-default", # custom addition
                             as_number=state.params['local_as'],
                             local_pref=state.params['local_preference'],
                             router_id=LOCAL_LOOPBACK,
                             best_path_change_handler=best_path_change_handler,
                             peer_up_handler=peer_up_handler,
                             peer_down_handler=peer_down_handler)

  # Add any static VTEPs/VNIs, before starting ARP thread
  for vni,mac_vrf in state.mac_vrfs.items():
     UpdateMACVRF( state, mac_vrf )

  logging.info( f"Connecting to neighbor {NEIGHBOR}..." )
  # TODO enable_four_octet_as_number=True, enable_enhanced_refresh=True
  state.speaker.neighbor_add( NEIGHBOR,
                              remote_as=state.params['peer_as'],
                              local_as=state.params['local_as'],
                              enable_ipv4=False, enable_evpn=True,
                              connect_mode='active') # iBGP with SRL

  # After connecting to BGP peer, start ARP thread (in different netns)
  eventlet.sleep(10) # Wait for peer_up event using peer_up_handler
  # hub.spawn( ARP_receiver_thread, speaker, params, evpn_vteps )

  while True:
     logging.info( "eventlet sleep loop..." )
     eventlet.sleep(30) # every 30s wake up

def AutoRouteDistinguisher( vtep_ip, mac_vrf ):
    # For RD, use the static VTEP's IP, just as would happen when it would
    # advertise the routes itself. This implies we need to create a VRF
    # per static VTEP locally
    return f"{vtep_ip}:{mac_vrf['evi']}"

def AutoRouteTarget( state, mac_vrf ):
    return f"{state.params['local_as']}:{mac_vrf['evi']}"

def Add_Static_VTEP( state, mac_vrf, remote_ip, dynamic=False ):
    rd = AutoRouteDistinguisher( remote_ip, mac_vrf )
    if rd not in state.bgp_vrfs:
       rt = AutoRouteTarget(state,mac_vrf)
       logging.info(f"Add_Static_VTEP: Adding VRF...RD={rd} RT={rt}")
       state.speaker.vrf_add(route_dist=rd,import_rts=[rt],export_rts=[rt],route_family=RF_L2_EVPN)
       state.bgp_vrfs[ rd ] = remote_ip
    else:
       logging.info(f"Add_Static_VTEP: Assuming VRF for RD={rd} exists...")

    js_path = f'.static_vxlan_agent.static_vtep{{.vtep_ip=="{remote_ip}"}}'
    now_ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
      'last_update' : { "value" : now_ts },
    }
    if dynamic:
       data['dynamic'] = { "value" : True }

    js_path2 = f'.static_vxlan_agent.static_vtep{{.vtep_ip=="{remote_ip}"}}.mac_vrf{{.name=="{mac_vrf["name"]}"}}'
    data2 = { 'evi': { 'value': mac_vrf['evi'] }, 'vni': { 'value': mac_vrf['vni'] } }
    Add_Telemetry( [(js_path, data),(js_path2,data2)] )

    logging.info("Adding EVPN multicast route...")
    #
    # For RD use the static VTEP's IP, just like it would do if it was
    # EVPN enabled itself. That way, any proxy will announce the same
    # route
    #
    AnnounceMulticastRoute( state, rd, remote_ip, mac_vrf['vni'] )
    return True

def Remove_Static_VTEP( state, mac_vrf, remote_ip, clear_macs=True ):

    rd = AutoRouteDistinguisher( remote_ip, mac_vrf )
    if rd not in state.bgp_vrfs:
        logging.warning( f"Remove_Static_VTEP: BGP MAC VRF does not exists: {rd}" )
        return False

    logging.info(f"Remove_Static_VTEP: Removing VRF...RD={rd}")

    # Deleting the VRF should withdraw all routes too? Doesn't look like it
    WithdrawMulticastRoute(state,rd,remote_ip)
    state.speaker.vrf_del(route_dist=rd)

    # This isn't sufficient
    js_path = f'.static_vxlan_agent.static_vtep{{.vtep_ip=="{remote_ip}"}}'
    js_path2 = f'.static_vxlan_agent.static_vtep{{.vtep_ip=="{remote_ip}"}}.mac_vrf{{.name=="{mac_vrf["name"]}"}}'
    Remove_Telemetry( [js_path,js_path2] )

    if clear_macs:
       del mac_vrf['vxlan_vteps'][ remote_ip ]
    del state.bgp_vrfs[ rd ]
    return True

##################################################################
## Proc to process the config Notifications received by auto_config_agent
## At present processing config from js_path containing agent_name
##################################################################
def Handle_Notification(obj, state):
    if obj.HasField('config'):
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")

        json_str = obj.config.data.json.replace("'", "\"")
        data = json.loads(json_str) if json_str != "" else {}

        # net_inst = obj.config.key.keys[0] # always "default"
        if obj.config.key.js_path == ".network_instance.protocols.static_vxlan_agent":
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            if obj.config.op == 2:
                logging.info(f"Delete config scenario")
                # TODO if this is the last namespace, unregister?
                # response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
                # logging.info( f'Handle_Config: Unregister response:: {response}' )
                # state = State() # Reset state, works?
                state.params[ "admin_state" ] = "disable" # Only stop service for this namespace
            else:
                # JvB there should be a helper for this
                if 'admin_state' in data:
                    state.params[ "admin_state" ] = data['admin_state'][12:]
                if 'local_as' in data:
                    state.params[ "local_as" ] = int( data['local_as']['value'] )
                if 'peer_as' in data:
                    state.params[ "peer_as" ] = int( data['peer_as']['value'] )
                if 'local_preference' in data:
                    state.params[ "local_preference" ] = int( data['local_preference']['value'] )
                if 'source_address' in data:
                    state.params[ "source_address" ] = data['source_address']['value']
                if 'peer_address' in data:
                    state.params[ "peer_address" ] = data['peer_address']['value']

            # if enabled, start separate thread for BGP EVPN interactions
            def shutdown_bgp():
                state.speaker.shutdown()
                del state.speaker
                state.bgp_vrfs = {} # Reset
                # state.mac_vrfs = {} do not clean this
                hub.kill( state.bgpThread )

            if state.params[ "admin_state" ] == "enable":
               # BGPEVPNThread().start()
               if hasattr( state, 'bgpThread' ):
                   shutdown_bgp()
                   logging.info( "old BGP thread shutdown" )

               state.bgpThread = hub.spawn( runBGPThread, state )
            elif hasattr( state, 'bgpThread' ):
               shutdown_bgp()
               del state.bgpThread
               Remove_Telemetry( [".static_vxlan_agent"] ) # Works?
               logging.info( "BGP shutdown" )

            return True

        elif obj.config.key.js_path == ".network_instance.protocols.bgp_evpn.bgp_instance.static_vxlan_agent":
          mac_vrf_name = obj.config.key.keys[0]

          admin_state = data['admin_state'][12:] if 'admin_state' in data else None
          vni = int( data['vni']['value'] ) if 'vni' in data else None
          evi = int( data['evi']['value'] ) if 'evi' in data else None

          # Index by VNI
          if vni:
            # Support VNI/EVI modifications
            new_vni = None
            new_evi = None

            if admin_state == "enable":
               if vni not in state.mac_vrfs and mac_vrf_name not in state.mac_vrfs:
                 vrf = { 'name': mac_vrf_name,
                         'admin_state': admin_state, 'vni': vni, 'evi': evi,
                         'macs': {}, 'ips': {}, 'vxlan_vteps': {}, 'path_probes': {} }
                 state.mac_vrfs[ vni ] = state.mac_vrfs[ mac_vrf_name ] = vrf
               else:
                 if vni not in state.mac_vrfs:
                    orig_vrf = state.mac_vrfs[ mac_vrf_name ]
                    new_vni = vni
                    logging.info( f"VNI modified on {mac_vrf_name}: {orig_vrf['vni']}->{vni}" )
                    state.mac_vrfs[ vni ] = orig_vrf
                    state.mac_vrfs.pop( orig_vrf['vni'], None )

                 if evi != state.mac_vrfs[ vni ][ 'evi' ]:
                    new_evi = evi
                    logging.info( f"EVI modified on {mac_vrf_name}: {state.mac_vrfs[ vni ][ 'evi' ]}->{new_evi}" )
               state.mac_vrfs[ vni ][ 'admin_state' ] = "enable"
               if hasattr( state, 'speaker' ): # BGP running?
                 UpdateMACVRF( state, state.mac_vrfs[ vni ], new_vni=new_vni, new_evi=new_evi )
               else:
                 logging.info( "BGP thread not running yet, postponing UpdateMACVRF" )
            else:
               logging.info( f"mac-vrf {mac_vrf_name} disabled, removing state" )
               if vni in state.mac_vrfs:
                   old_vrf = state.mac_vrfs[ vni ]
               elif mac_vrf_name in state.mac_vrfs:
                   old_vrf = state.mac_vrfs[ mac_vrf_name ]
                   vni = old_vrf['vni']
               else:
                   return
               old_vrf[ "admin_state" ] = "disable"
               UpdateMACVRF( state, old_vrf )
               state.mac_vrfs.pop( vni, None )
               state.mac_vrfs.pop( old_vrf['name'], None )
        elif obj.config.key.js_path == ".network_instance.protocols.bgp_evpn.bgp_instance.static_vxlan_agent.static_vtep":
          mac_vrf_name = obj.config.key.keys[0]
          vtep_ip = obj.config.key.keys[2]
          if mac_vrf_name in state.mac_vrfs:
            mac_vrf = state.mac_vrfs[ mac_vrf_name ]
            if obj.config.op == 2: # delete static VTEP
              # All MAC routes get withdrawn too
              Remove_Static_VTEP( state, mac_vrf, vtep_ip, clear_macs=True )
            else:
              static_macs = {}
              if 'static_vtep' in data and 'static_macs' in data['static_vtep']:
                static_macs = { m['value'] : "static"
                                for m in data['static_vtep']['static_macs'] }

              UpdateMACVRF_StaticVTEP( state, mac_vrf, vtep_ip, static_macs )
          else:
              logging.error( f"mac-vrf not found in state: {mac_vrf_name}" )
        else:
            logging.warning( f"Unmatched config path: {obj.config.key.js_path}" )
    else:
       logging.info(f"Unexpected notification (no config) : {obj}")

    return False

class State(object):
    def __init__(self):
        self.params = { 'include_ip': False }  # Set through config
        self.bgp_vrfs = {}
        self.mac_vrfs = {} # Map of vni -> mac-vrf { vxlan_vteps, evi, learned macs }

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

##################################################################################################
## This is the main proc where all processing for auto_config_agent starts.
## Agent registration, notification registration, Subscrition to notifications.
## Waits on the subscribed Notifications and once any config is received, handles that config
## If there are critical errors, Unregisters the fib_agent gracefully.
##################################################################################################
def Run():
    sub_stub = sdk_service_pb2_grpc.SdkNotificationServiceStub(channel)

    # optional agent_liveliness=<seconds> to have system kill unresponsive agents
    response = stub.AgentRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
    logging.info(f"Registration response : {response.status}")

    request=sdk_service_pb2.NotificationRegisterRequest(op=sdk_service_pb2.NotificationRegisterRequest.Create)
    create_subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    stream_id = create_subscription_response.stream_id
    logging.info(f"Create subscription response received. stream_id : {stream_id}")

    try:
      Subscribe_Notifications(stream_id)

      stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
      stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

      state = State()
      count = 1

      for r in stream_response:
        logging.info(f"Count :: {count}  NOTIFICATION:: \n{r.notification}")
        count += 1
        for obj in r.notification:
            if obj.HasField('config') and obj.config.key.js_path == ".commit.end":
                logging.info('TO DO -commit.end config')
            else:
                Handle_Notification(obj, state)
                logging.info(f'Updated state: {state}')

    except grpc._channel._Rendezvous as err:
        logging.info(f'GOING TO EXIT NOW: {err}')

    except Exception as e:
        logging.error(f'Exception caught :: {e}')
        #if file_name != None:
        #    Update_Result(file_name, action='delete')
        try:
            response = stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
            logging.error(f'Run try: Unregister response:: {response}')
        except grpc._channel._Rendezvous as err:
            logging.info(f'GOING TO EXIT NOW: {err}')
            sys.exit()
        return True
    sys.exit()
    return True
############################################################
## Gracefully handle SIGTERM signal
## When called, will unregister Agent and gracefully exit
############################################################
def Exit_Gracefully(signum, frame):
    logging.info( f"Caught signal :: {signum}\n will unregister EVPN proxy agent" )
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.info( f'Exit_Gracefully: Unregister response:: {response}' )
    finally:
        logging.info( f'GOING TO EXIT NOW' )
        sys.exit()

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/static_vxlan_agent.log
## Signals handled for graceful exit: SIGTERM
##################################################################################################
if __name__ == '__main__':

    # grpc_eventlet.init_eventlet() # Fix gRPC eventlet interworking

    # hostname = socket.gethostname()
    stdout_dir = '/var/log/srlinux/stdout' # PyTEnv.SRL_STDOUT_DIR
    signal.signal(signal.SIGTERM, Exit_Gracefully)
    if not os.path.exists(stdout_dir):
        os.makedirs(stdout_dir, exist_ok=True)
    log_filename = f'{stdout_dir}/{agent_name}.log'
    logging.basicConfig(
      handlers=[RotatingFileHandler(log_filename, maxBytes=3000000,backupCount=5)],
      format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
      datefmt='%H:%M:%S', level=logging.INFO)
    logging.info("START TIME :: {}".format(datetime.now()))
    if Run():
        logging.info('Agent unregistered and BGP shutdown')
    else:
        logging.info('Should not happen')
