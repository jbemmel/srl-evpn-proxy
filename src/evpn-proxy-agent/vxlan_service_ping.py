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
    logging.info( f"JvB2: do_service_ping arguments={arguments}" )

    # For each uplink interface in default vrf:
    # 1. Get MAC and peer MAC
    # 2. Pass MACs to agent config (or open raw socket and send ARP packet here)

    # open UDP socket and have OS figure out MAC addresses
    # Run a separate, simple Python binary
    with netns.NetNS(nsname="srbase-default"):
      socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      socket.bind( 'e1-1.0', 12345 ) # Set source port
      socket.sendto( "Hello".encode(), ("1.1.1.7", 4789) )
