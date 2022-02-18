#!/usr/bin/python
###########################################################################
# Description:
#
# Copyright (c) 2021 Nokia
###########################################################################
from srlinux.mgmt.cli import ExecuteError
from srlinux.mgmt.cli.tools_plugin import ToolsPlugin
from srlinux.mgmt.cli.required_plugin import RequiredPlugin
from srlinux.mgmt.cli import KeyCompleter
from srlinux.syntax import Syntax
from srlinux.location import build_path
from srlinux.mgmt.cli.plugins.bash_network_command_helper import execute_network_command
from srlinux import child_process
from srlinux.schema import DataStore

import sys
# sys.path.append('/usr/local/lib/python3.6/site-packages') # for netns
import logging # , socket, netns

#
# L2 service ping using custom ARP packets
#
class Plugin(ToolsPlugin):

    # Provide list of plugins that must be loaded before this one
    def get_required_plugins(self):
        return [RequiredPlugin("tools_mode")]

    # Define where this command exists in the command hierarchy in sr_cli
    def on_tools_load(self, state):
        # Could also add it under /tools network-instance
        if state.system_features.vxlan:
           root = state.command_tree.tools_mode.root
           root.add_command(self._get_syntax(state), update_location=False, callback=do_service_ping)
        # system = state.command_tree.tools_mode.root.get_command('system')
        # system.add_command(self._get_syntax(), update_location=False, callback=do_service_ping)
        else:
            logging.warning( "VXLAN feature not enabled for this system" )

    # Helper function to get arguments and help strings for this plugin command
    def _get_syntax(self,state):
        syntax = Syntax("vxlan-service-ping", help="Pings other VXLAN VTEPs in a given L2 overlay service")
        syntax.add_named_argument('mac-vrf', help="target mac-vrf used to lookup the VNI",
          suggestions=KeyCompleter(path='/network-instance[name=*]')) # Cannot select type=mac-vrf only?

        # Dont allow specific VNI directly, we need to know service context with VTEPs
        # syntax.add_named_argument('vni', default="0", help="specific vni to use (instead of lookup by mac-vrf)",
        #  suggestions=KeyCompleter(path='/tunnel-interface[name=*]/vxlan-interface[index=*]/ingress/vni'))

        # Lookup vxlan interface for given mac-vrf - seems to deadlock
        def _get_vteps_in_vrf(arguments):
          mac_vrf = arguments.get_or('mac-vrf','*')
          # logging.info( f"_get_path args={arguments} mac_vrf={mac_vrf}" )
          if mac_vrf!='*':
             vxlan_intf = get_vxlan_interface(state,mac_vrf)
             tun = vxlan_intf.split('.')
          else:
             tun = ['*','*']
          # Could lookup VNI here too
          return build_path(f'/tunnel-interface[name={tun[0]}]/vxlan-interface[index={tun[1]}]/bridge-table/multicast-destinations/destination[vtep=*][vni=*]')

        # Hardcoded
        syntax.add_named_argument('vtep', default='*',
           # suggestions=KeyCompleter(path=_get_vteps_in_vrf,keyname='vtep') )
           # suggestions=KeyCompleter(path='/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/bridge-table/multicast-destinations/destination[vtep=*]') )
           suggestions=KeyCompleter(path='/tunnel-interface[name=*]/vxlan-interface[index=*]/bridge-table/multicast-destinations/destination[vtep=*]') )

        syntax.add_unnamed_argument('target-ip', default="", help="Perform a ping to this destination IP(/subnet). Format: <ip>[/prefix]\n"+
                                                                  "e.g. '10.0.0.254' or '10.0.0.254/24' (latter uses .254 as source)" )
        syntax.add_named_argument('src-ip', default="", help="Perform a ping from this source IP" )

        def _get_learnt_macs_in_vrf(arguments):
           mac_vrf = arguments.get('vxlan-service-ping', 'mac-vrf')
           # logging.info( f"_get_learnt_macs_in_vrf args={arguments} mac_vrf={mac_vrf}" )
           return build_path(f'/network-instance[name={mac_vrf}]/bridge-table/mac-learning/learnt-entries/mac[address=*]')

        syntax.add_named_argument('src-mac', default="", help="Source MAC to use, auto-completed based on locally learnt MAC addresses",
           suggestions=KeyCompleter(path=_get_learnt_macs_in_vrf) )
           # suggestions=KeyCompleter(path='/tunnel-interface[name=vxlan0]/vxlan-interface[index=0]/bridge-table/multicast-destinations/destination[vtep=*]') )
           # suggestions=KeyCompleter(path='/network-instance[name=*]/bridge-table/mac-learning/learnt-entries[mac=*]') )

        syntax.add_named_argument('entropy', default="0", help="Provide extra input to ECMP hashing, added to UDP source port")

        syntax.add_boolean_argument('debug', help="Enable additional debug output")
        syntax.add_boolean_argument('icmp', help="Use ICMP instead of ARP")

        # TODO add 'count' argument, default 3
        return syntax

# end class VxlanServicePing

def get_vxlan_interface(state,mac_vrf):
   path = build_path(f'/network-instance[name={mac_vrf}]/protocols/bgp-evpn/bgp-instance[id=1]/vxlan-interface')
   data = state.server_data_store.get_data(path, recursive=True)
   return data.network_instance.get().protocols.get().bgp_evpn.get().bgp_instance.get().vxlan_interface

    # Callback that runs when the plugin is run in sr_cli
def do_service_ping(state, input, output, arguments, **_kwargs):
    logging.info( f"do_service_ping arguments={arguments}" )

    # For each uplink interface in default vrf:
    # 1. Get MAC and peer MAC
    # 2. Pass MACs to agent config (or open raw socket and send ARP packet here)

    mac_vrf = arguments.get('vxlan-service-ping', 'mac-vrf')
    vtep = arguments.get('vxlan-service-ping', 'vtep')
    # vni = int( arguments.get('vxlan-service-ping', 'vni') )
    ping_ip = arguments.get('vxlan-service-ping', 'target-ip')
    ping_src_ip = arguments.get('vxlan-service-ping', 'src-ip')
    ping_src_mac = arguments.get('vxlan-service-ping', 'src-mac')
    entropy = int( arguments.get('vxlan-service-ping', 'entropy') )
    debug = arguments.get('vxlan-service-ping', 'debug')
    icmp = arguments.get('vxlan-service-ping', 'icmp')

    if bool(ping_src_mac) ^ bool(ping_ip):
        raise ExecuteError( "ping-src-mac and destination ip must be provided together" )
    if icmp and not bool(ping_ip):
        raise ExecuteError( "Destination ip must be provided for ICMP" )
    if ping_ip and not '/' in ping_ip and not ping_src_ip:
        raise ExecuteError( "Source ip must be provided for single destination IP" )

    def get_vni(vxlan_intf):
       tun = vxlan_intf.split('.')
       path = build_path(f'/tunnel-interface[name={tun[0]}]/vxlan-interface[index={tun[1]}]/ingress/vni')
       data = state.server_data_store.get_data(path, recursive=True)
       return data.tunnel_interface.get().vxlan_interface.get().ingress.get().vni

    def get_uplinks():
       logging.info( f"vxlan-service-ping: Listing all uplinks in 'default' network-instance" )
       # XXX hardcoded assumption it is called 'default'
       path = build_path(f'/network-instance[name=default]/interface[name=e*]')
       data = state.server_data_store.get_data(path, recursive=True)
       return [ i.name.replace('ethernet-','e').replace('/','-')
                for i in data.network_instance.get().interface.items() ]

    def get_system0_vtep_ip():
       path = build_path('/interface[name=system0]/subinterface[index=0]/ipv4/address')
       data = state.server_data_store.get_data(path, recursive=True)
       return data.interface.get().subinterface.get().ipv4.get().address.get().ip_prefix.split('/')[0]

    # Need to access State
    def get_evpn_vteps(vxlan_intf):
       logging.info( f"vxlan-service-ping: Listing VTEPs associated with VXLAN interface {vxlan_intf}" )
       # path = build_path('/vxlan-agent/evpn-vteps')
       tun = vxlan_intf.split('.')
       path = build_path(f'/tunnel-interface[name={tun[0]}]/vxlan-interface[index={tun[1]}]/bridge-table/multicast-destinations/destination')
       # logging.info( f"Current store: {state.data_store}")
       data = state.server.get_data_store( DataStore.State ).get_data(path, recursive=True)
       return [ p.vtep for p in data.tunnel_interface.get().vxlan_interface.get().bridge_table.get().multicast_destinations.get().destination.items() ]

    vxlan_intf = get_vxlan_interface(state,mac_vrf)
    vni = get_vni(vxlan_intf)
    local_vtep = get_system0_vtep_ip()
    uplinks = ",".join( get_uplinks() )
    dest_vteps = vtep if vtep!='*' else ",".join( get_evpn_vteps(vxlan_intf) )

    # open UDP socket and have OS figure out MAC addresses
    # Run a separate, simple Python binary in the default namespace
    # Need sudo
    proto = "icmp" if icmp else "arp"
    cmd = f"ip netns exec srbase-default /usr/bin/sudo -E /usr/bin/python3 /opt/demo-agents/evpn-proxy-agent/vxping.py {proto} {vni} {local_vtep} {entropy} {uplinks} {dest_vteps} {ping_ip} {ping_src_mac} {ping_src_ip}"
    logging.info( f"vxlan-service-ping: bash {cmd}" )
    exit_code = child_process.run( cmd.split(), output=output )
