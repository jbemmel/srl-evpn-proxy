#!/usr/bin/python
###########################################################################
# Description:
#
# Copyright (c) 2021 Nokia
###########################################################################
from srlinux.mgmt.cli.tools_plugin import ToolsPlugin
from srlinux.mgmt.cli.required_plugin import RequiredPlugin
from srlinux.mgmt.cli import KeyCompleter
from srlinux.syntax import Syntax
from srlinux.location import build_path
from srlinux.mgmt.cli.plugins.bash_network_command_helper import execute_network_command
from srlinux import child_process
from srlinux.schema import DataStore

import sys
sys.path.append('/usr/local/lib/python3.6/site-packages') # for netns
import logging, socket, netns

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
        root = state.command_tree.tools_mode.root
        root.add_command(self._get_syntax(), update_location=False, callback=do_service_ping)
        # system = state.command_tree.tools_mode.root.get_command('system')
        # system.add_command(self._get_syntax(), update_location=False, callback=do_service_ping)

    # Helper function to get arguments and help strings for this plugin command
    def _get_syntax(self):
        syntax = Syntax("vxlan-service-ping", help="Pings other VXLAN VTEPs in a given L2 overlay service")
        syntax.add_named_argument('mac-vrf', suggestions=KeyCompleter(path='/network-instance[name=*]')) # Cannot select type=mac-vrf only?
        syntax.add_unnamed_argument(name='vtep', default='*') # TODO Lookup in state published by evpn agent

        # TODO add 'count' argument, default 3
        return syntax

    # Example from reports/tunnel_interface_reports.py
    def _fetch_state_vxlan_unicast(self, state, arguments, recurse=True):
        tunnel_interface = arguments.get('tunnel-interface', 'interface')
        vxlan_interface = arguments.get('vxlan-interface', 'index')
        vtep = arguments.get('destination', 'vtep') if arguments.has_node('destination') else '*'
        vni = arguments.get('destination', 'vni') if arguments.has_node('destination') else '*'
        path = build_path(f'/tunnel-interface[name={tunnel_interface}]/vxlan-interface[index={vxlan_interface}]/bridge-table/unicast-destinations/destination[vtep={vtep}][vni={vni}]')
        return state.server_data_store.stream_data(path, recursive=recurse)

# end class VxlanServicePing

    # Callback that runs when the plugin is run in sr_cli
def do_service_ping(state, input, output, arguments, **_kwargs):
    logging.info( f"JvB: do_service_ping arguments={arguments}" )

    # For each uplink interface in default vrf:
    # 1. Get MAC and peer MAC
    # 2. Pass MACs to agent config (or open raw socket and send ARP packet here)

    mac_vrf = arguments.get('vxlan-service-ping', 'mac-vrf')

    def get_vxlan_interface():
       path = build_path(f'/network-instance[name={mac_vrf}]/protocols/bgp-evpn/bgp-instance[id=1]/vxlan-interface')
       data = state.server_data_store.get_data(path, recursive=True)
       return data.network_instance.get().protocols.get().bgp_evpn.get().bgp_instance.get().vxlan_interface

    def get_vni(vxlan_intf):
       tun = vxlan_intf.split('.')
       path = build_path(f'/tunnel-interface[name={tun[0]}]/vxlan-interface[index={tun[1]}]/ingress/vni')
       data = state.server_data_store.get_data(path, recursive=True)
       return data.tunnel_interface.get().vxlan_interface.get().ingress.get().vni

    def get_uplinks():
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
       # path = build_path('/vxlan-agent/evpn-vteps')
       tun = vxlan_intf.split('.')
       path = build_path(f'/tunnel-interface[name={tun[0]}]/vxlan-interface[index={tun[1]}]/bridge-table/multicast-destinations/destination')
       logging.info( f"Current store: {state.data_store}")
       data = state.server.get_data_store( DataStore.State ).get_data(path, recursive=True)
       return [ p.vtep for p in data.tunnel_interface.get().vxlan_interface.get().bridge_table.get().multicast_destinations.get().destination.items() ]

    vxlan_intf = get_vxlan_interface()
    vni = get_vni(vxlan_intf)
    local_vtep = get_system0_vtep_ip()
    uplinks = ",".join( get_uplinks() )
    dest_vteps = ",".join( get_evpn_vteps(vxlan_intf) )

    # open UDP socket and have OS figure out MAC addresses
    # Run a separate, simple Python binary in the default namespace
    # Need sudo
    cmd = f"ip netns exec srbase-default /usr/bin/sudo -E /usr/bin/python3 /opt/demo-agents/evpn-proxy-agent/vxping.py {vni} {local_vtep} {uplinks} {dest_vteps}"
    exit_code = child_process.run( cmd.split(), output=output )
