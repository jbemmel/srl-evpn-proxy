#!/usr/bin/env python
# coding=utf-8

import grpc
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
import eventlet
import signal
from ryu.services.protocols.bgp.bgpspeaker import (BGPSpeaker,
                                                  EVPN_MULTICAST_ETAG_ROUTE,
                                                  EVPN_MAC_IP_ADV_ROUTE,
                                                  RF_L2_EVPN,
                                                  PMSI_TYPE_INGRESS_REP)

# BGPSpeaker needs sockets patched
eventlet.monkey_patch()

############################################################
## Agent will start with this name
############################################################
agent_name='evpn_proxy_agent'

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
    print('Status of subscription response for {}:: {}'.format(option, subscription_response.status))

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
# Runs BGP EVPN as a separate thread
#
from threading import Thread
class BGPEVPNThread(Thread):
   def __init__(self):
       Thread.__init__(self)

   def run(self):
     LOCAL_LOOPBACK = '1.1.1.4' # TODO remove hardcoded values
     VTEP_LOOPBACK = '1.1.1.2'
     AS = 65000
     VNI = 10

     def best_path_change_handler(event):
         logging.info( 'The best path changed:',
           event.remote_as, event.prefix, event.nexthop, event.is_withdraw, event.path )

     def peer_down_handler(remote_ip, remote_as):
         logging.warning( f'Peer down: {remote_ip} {remote_as}' )

     # need to create socket on localhost on a non-default port, not port 179
     # Need to connect from loopback IP, not 127.0.0.x
     # Router ID is used as tunnel endpoint in BGP UPDATEs
     # => Code updated to allow any tunnel endpoint IP
     speaker = BGPSpeaker(bgp_server_hosts=[LOCAL_LOOPBACK], bgp_server_port=1179,
                               as_number=AS, router_id=LOCAL_LOOPBACK,
                               best_path_change_handler=best_path_change_handler,
                               peer_down_handler=peer_down_handler)
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
         pmsi_tunnel_type=PMSI_TYPE_INGRESS_REP,

         # Added via patch
         tunnel_endpoint_ip='1.2.3.4'
     )

     logging.info( "Connecting as local SRL neighbor..." )
     # TODO enable_four_octet_as_number=True, enable_enhanced_refresh=True
     speaker.neighbor_add(LOCAL_LOOPBACK, remote_as=AS, local_as=AS, enable_ipv4=False,
       enable_evpn=True, connect_mode='active') # iBGP with SRL

     while True:
         eventlet.sleep(30) # every 30s wake up

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
                if 'admin_state' in data:
                    state.params[ "admin_state" ] = data['admin_state'][12:]

            # TODO if enabled, start separate thread for BGP EVPN interactions
            return True

    else:
        logging.info(f"Unexpected notification : {obj}")

    # dont subscribe to LLDP now
    return False

class State(object):
    def __init__(self):
        self.admin_state = None       # May not be set in config
        self.network_instances = {}   # Indexed by name
        # TODO more properties

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

    Subscribe_Notifications(stream_id)

    stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
    stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

    state = State()
    count = 1
    try:
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
    logging.info("Caught signal :: {}\n will unregister EVPN proxy agent".format(signum))
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.error('try: Unregister response:: {}'.format(response))
        sys.exit()
    except grpc._channel._Rendezvous as err:
        logging.info('GOING TO EXIT NOW: {}'.format(err))
        sys.exit()

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/evpn_proxy_agent.log
## Signals handled for graceful exit: SIGTERM
##################################################################################################
if __name__ == '__main__':
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
