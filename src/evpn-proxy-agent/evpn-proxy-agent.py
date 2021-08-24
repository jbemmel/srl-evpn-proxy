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

import datetime
import time
import sys
import logging
import socket
import os
import re
import ipaddress
import json
import traceback
import subprocess
# from concurrent.futures import ThreadPoolExecutor
import pwd

# sys.path.append('/usr/lib/python3.6/site-packages/sdk_protos')
import sdk_service_pb2
import sdk_service_pb2_grpc
import lldp_service_pb2
import config_service_pb2
import sdk_common_pb2

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

# Ryu has its own threading model
from ryu.lib import hub

#
# eBPF ARP filter imports
#
from bcc import BPF
from ryu.lib.packet import packet, ipv4, vxlan, ethernet, arp

############################################################
## Agent will start with this name
############################################################
agent_name='srl_evpn_proxy_agent'

############################################################
## Open a GRPC channel to connect to sdk_mgr on the dut
## sdk_mgr will be listening on 50053
############################################################
#channel = grpc.insecure_channel('unix:///opt/srlinux/var/run/sr_sdk_service_manager:50053')
channel = grpc.insecure_channel('127.0.0.1:50053')
metadata = [('agent_name', agent_name)]
stub = sdk_service_pb2_grpc.SdkMgrServiceStub(channel)

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

#
# Runs BGP EVPN as a separate thread>, using Ryu hub
#
#from threading import Thread
#class BGPEVPNThread(Thread):
#   def __init__(self):
#       Thread.__init__(self)

def runBGPThread( params ):
  LOCAL_LOOPBACK = params['source_address'] # TODO remove hardcoded values
  NEIGHBOR = params[ 'peer_address' ]
  if NEIGHBOR=="127.0.0.1": # Connect to 127.0.0.1 does not work
     NEIGHBOR = LOCAL_LOOPBACK

  evpn_vteps = {}
  def best_path_change_handler(event):
      logging.info( f'The best path changed: {event.path}' )
        # event.remote_as, event.prefix, event.nexthop, event.is_withdraw, event.path )
      if event.is_withdraw:
         evpn_vteps.pop( event.nexthop, None )
      else:
         evpn_vteps[ event.nexthop ] = event.remote_as

  def peer_down_handler(remote_ip, remote_as):
      logging.warning( f'Peer down: {remote_ip} {remote_as}' )
  # need to create socket on localhost on a non-default port, not port 179
  # Need to connect from loopback IP, not 127.0.0.x
  # Router ID is used as tunnel endpoint in BGP UPDATEs
  # => Code updated to allow any tunnel endpoint IP
  logging.info("Starting BGP thread in srbase-default netns...")
  # Requires root permissions
  with netns.NetNS(nsname="srbase-default"):
     logging.info("Starting BGPSpeaker in netns...")

     speaker = BGPSpeaker(bgp_server_hosts=[LOCAL_LOOPBACK], bgp_server_port=1179,
                               as_number=params['local_as'], router_id=LOCAL_LOOPBACK,
                               best_path_change_handler=best_path_change_handler,
                               peer_down_handler=peer_down_handler)

     logging.info( f"Connecting to neighbor {NEIGHBOR}..." )
     # TODO enable_four_octet_as_number=True, enable_enhanced_refresh=True
     speaker.neighbor_add( NEIGHBOR, remote_as=params['peer_as'],
                           local_as=params['local_as'], enable_ipv4=False,
                           enable_evpn=True, connect_mode='active') # iBGP with SRL

     # After connecting to BGP peer, start ARP thread (in different netns)
     eventlet.sleep(10) # Could also wait for peer_up event...
     hub.spawn( ARP_receiver_thread, params['vxlan_interface'], speaker,
       LOCAL_LOOPBACK, params['local_as'], params['vnis'], evpn_vteps )

     while True:
         logging.info( "eventlet sleep loop..." )
         eventlet.sleep(30) # every 30s wake up

def ARP_receiver_thread( interface, bgp_speaker, router_id, ibgp_as, vnis, evpn_vteps ):
    logging.info( f"Starting ARP listener on {interface} router_id={router_id} AS={ibgp_as} vnis={vnis}" )
    # initialize BPF - load source code from filter-vxlan-arp.c
    bpf = BPF(src_file = "filter-vxlan-arp.c",debug = 0)

    #load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
    #more info about eBPF program types
    #http://man7.org/linux/man-pages/man2/bpf.2.html
    function_arp_filter = bpf.load_func("vxlan_arp_filter", BPF.SOCKET_FILTER)

    mac_vrfs = {} # Announced MAC VRFs indexed by static VTEP IP

    #create raw socket, bind it to interface
    #attach bpf program to socket created
    with netns.NetNS(nsname="srbase"):
      BPF.attach_raw_socket(function_arp_filter, interface)
      socket_fd = function_arp_filter.sock
      sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
      sock.setblocking(True)
      while 1:
        packet_str = os.read(socket_fd,2048)
        packet_bytearray = bytearray(packet_str)
        try:
          pkt = packet.Packet( packet_bytearray )
          #
          # 6 layers:
          # 0: ethernet
          # 1: IP                  -> VTEP IP (other side, local VTEP)
          # 2: UDP
          # 3: VXLAN               -> VNI
          # 4: ethernet (inner)
          # 5: ARP                 -> MAC, IP
          #
          for p in pkt:
              logging.info( f"ARP packet:{p.protocol_name}={p}" )
              if p.protocol_name == 'vlan':
                  logging.info( f'vlan id = {p.vid}' )
              elif p.protocol_name == 'vxlan':
                  logging.info( f'vni = {p.vni}' )

          _ip = pkt.get_protocol( ipv4.ipv4 )
          _vxlan = pkt.get_protocol( vxlan.vxlan )
          _arp = pkt.get_protocol( arp.arp )

          vni = _vxlan.vni

          if vnis!='*' and vni not in vnis:
              logging.info( f"VNI not enabled for proxy EVPN: {vni}" )
              continue;

          if _ip.src in evpn_vteps:
             logging.info( "ARP from EVPN VTEP -> ignoring" )
             continue
          elif _ip.dst in evpn_vteps: # typically == us, always?
             static_vtep = _ip.src
             if _arp.opcode == 1:
               mac = _arp.src_mac
               ip = _arp.src_ip
               logging.info( f"ARP request from static VTEP: {mac} {ip}" )
             elif _arp.opcode == 2:
               mac = _arp.dst_mac
               ip = _arp.dst_ip
               logging.info( f"ARP response from static VTEP: {mac} {ip}" )
             else:
               logging.info( f"ARP with unsupported opcode: {_arp.opcode} -> ignoring" )
               continue
          else:
             logging.info( f"ARP packet:neither src={_ip.src} nor dst={_ip.dst} is EVPN vtep?" )
             continue;

          # Announce EVPN route(s)
          vni_2_mac = mac_vrfs[ static_vtep ] if static_vtep in mac_vrfs else {}

          rd = f"{router_id}:{vni}"
          if vni not in vni_2_mac:
              rt = f"{ibgp_as}:{vni}"
              logging.info(f"Adding VRF...RD={rd} RT={rt}")
              bgp_speaker.vrf_add(route_dist=rd,import_rts=[rt],export_rts=[rt],route_family=RF_L2_EVPN)
              logging.info("Adding EVPN multicast route...")
              bgp_speaker.evpn_prefix_add(
                  route_type=EVPN_MULTICAST_ETAG_ROUTE,
                  route_dist=rd,
                  # esi=0, # should be ignored
                  ethernet_tag_id=0,
                  # mac_addr='00:11:22:33:44:55', # not relevant?
                  ip_addr=static_vtep, # origin
                  tunnel_type='vxlan',
                  vni=vni,
                  gw_ip_addr=static_vtep,
                  next_hop=static_vtep, # on behalf of remote VTEP
                  pmsi_tunnel_type=PMSI_TYPE_INGRESS_REP,
                  # Added via patch
                  tunnel_endpoint_ip=static_vtep
              )
              mac_table = [ { mac : ip } ]
              mac_vrfs[ static_vtep ] = vni_2_mac = { vni: mac_table }
          else:
              mac_table = vni_2_mac[ vni ]
              if mac in mac_table:
                  logging.info( f"MAC {mac} already announced, skipping" )
                  continue
              mac_table.update( { mac : ip } )

          logging.info( f"Announcing EVPN MAC route...evpn_vteps={evpn_vteps}" )

          # TODO add RT as extended community?
          bgp_speaker.evpn_prefix_add(
              route_type=EVPN_MAC_IP_ADV_ROUTE, # RT2
              route_dist=rd,
              esi=0,
              ethernet_tag_id=0,
              mac_addr=mac,
              ip_addr=ip, # TODO for mac-vrf service, omit this?
              next_hop=static_vtep, # on behalf of remote VTEP
              tunnel_type='vxlan',
              vni=vni,
              gw_ip_addr=static_vtep,
          )

        except Exception as e:
          print( f"Not a valid VXLAN packet? {e}" )

        # Debug - requires '/sys/kernel/debug/tracing/trace_pipe' to be mounted
        # (task, pid, cpu, flags, ts, msg) = bpf.trace_fields( nonblocking=True )
        # print( f'trace_fields: {msg}' )

##################################################################
## Proc to process the config Notifications received by auto_config_agent
## At present processing config from js_path containing agent_name
##################################################################
def Handle_Notification(obj, state):
    if obj.HasField('config') and obj.config.key.js_path != ".commit.end":
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")

        # net_inst = obj.config.key.keys[0] # always "default"
        if obj.config.key.js_path == ".network_instance.protocols.experimental_bgp_evpn_proxy":
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            state.params = {}
            if obj.config.op == 2:
                logging.info(f"Delete config scenario")
                # TODO if this is the last namespace, unregister?
                # response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
                # logging.info( f'Handle_Config: Unregister response:: {response}' )
                # state = State() # Reset state, works?
                state.params[ "admin_state" ] = "disable" # Only stop service for this namespace
            else:
                json_acceptable_string = obj.config.data.json.replace("'", "\"")
                data = json.loads(json_acceptable_string)

                # JvB there should be a helper for this
                if 'admin_state' in data:
                    state.params[ "admin_state" ] = data['admin_state'][12:]
                if 'local_as' in data:
                    state.params[ "local_as" ] = int( data['local_as']['value'] )
                if 'peer_as' in data:
                    state.params[ "peer_as" ] = int( data['peer_as']['value'] )
                if 'source_address' in data:
                    state.params[ "source_address" ] = data['source_address']['value']
                if 'peer_address' in data:
                    state.params[ "peer_address" ] = data['peer_address']['value']
                if 'vxlan_interface' in data:
                    state.params[ "vxlan_interface" ] = data['vxlan_interface']['value']
                if 'vnis' in data:
                    state.params[ "vnis" ] = [ int(e['value']) for e in data['vnis'] ]
                else:
                    state.params[ "vnis" ] = '*' # all

            # if enabled, start separate thread for BGP EVPN interactions
            if state.params[ "admin_state" ] == "enable":
               # BGPEVPNThread().start()
               if has_attr( state, 'bgpThread' ):
                   hub.kill( state.bgpThread )
                   # TODO cleanup ARP thread too, use link() ?
               state.bgpThread = hub.spawn( runBGPThread, state.params )
            elif has_attr( state, 'bgpThread' ):
               hub.kill( state.bgpThread )
               del state.bgpThread
               # TODO cleanup ARP thread too, use link() ?
               
               # Doesn't work - parallel netns calls
               # hub.spawn( ARP_receiver_thread, "e1-1" )
            return True

    else:
        logging.info(f"Unexpected notification : {obj}")

    return False

class State(object):
    def __init__(self):
        self.params = {}       # Set through config

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
        logging.error( f'try: Unregister response:: {response}' )
        sys.exit()
    except grpc._channel._Rendezvous as err:
        logging.info( f'GOING TO EXIT NOW: {err}' )
        sys.exit()

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/evpn_proxy_agent.log
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
    logging.info("START TIME :: {}".format(datetime.datetime.now()))
    if Run():
        logging.info('Agent unregistered and BGP shutdown')
    else:
        logging.info('Should not happen')
