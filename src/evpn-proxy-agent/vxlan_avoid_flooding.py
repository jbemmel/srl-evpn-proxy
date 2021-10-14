#!/usr/bin/python
###########################################################################
# Description: A CLI extension to help associate dynamically learnt MAC
# addresses with a static VTEP, such that flooding towards such MACs can be
# avoided
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
from srlinux.mgmt.cli.plugins.insert import _fetch_existing_leaflist_values
from srlinux import child_process
from srlinux.schema import DataStore

import sys
import logging
import json

#
# Helper tool to convert dynamically learnt MAC addresses to static config
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
           root.add_command(self._get_syntax(state), update_location=False, callback=do_flood_protect)
        # system = state.command_tree.tools_mode.root.get_command('system')
        # system.add_command(self._get_syntax(), update_location=False, callback=do_service_ping)
        else:
            logging.warning( "VXLAN feature not enabled for this system" )

    # Helper function to get arguments and help strings for this plugin command
    def _get_syntax(self,state):
        syntax = Syntax("vxlan-avoid-flooding", help="Prevents packet flooding by associating a MAC with a specific static VTEP")
        syntax.add_unnamed_argument('mac-vrf', help="target mac-vrf to operate on",
          suggestions=KeyCompleter(path='/network-instance[name=*]')) # Cannot select type=mac-vrf only?

        # Lookup static VTEPs provisioned for given mac-vrf
        def _get_vteps_in_vrf(arguments):
          mac_vrf = arguments.get_or('mac-vrf','*')
          return build_path(f'/network-instance[name={mac_vrf}]/protocols/bgp-evpn/bgp-instance[id=1]/vxlan-agent/static-vtep[vtep-ip=*]')

        # Pick from the static VTEPs configured for this mac-vrf
        syntax.add_named_argument('vtep',
           suggestions=KeyCompleter(path=_get_vteps_in_vrf,data_store=DataStore.Running) )

        def _get_learnt_macs_in_vrf(arguments):
           mac_vrf = arguments.get_or('mac-vrf','*')
           # logging.info( f"_get_learnt_macs_in_vrf args={arguments} mac_vrf={mac_vrf}" )
           return build_path(f'/network-instance[name={mac_vrf}]/bridge-table/mac-learning/learnt-entries/mac[address=*]')

        syntax.add_named_argument('mac', help="Dynamic MAC to associate with static VTEP",
           suggestions=KeyCompleter(path=_get_learnt_macs_in_vrf) )

        return syntax

# end class VxlanAvoidFlooding

    # Callback that runs when the plugin is run in sr_cli
def do_flood_protect(state, input, output, arguments, **_kwargs):
    logging.info( f"do_flood_protect arguments={arguments}" )

    # For each uplink interface in default vrf:
    # 1. Get MAC and peer MAC
    # 2. Pass MACs to agent config (or open raw socket and send ARP packet here)

    mac_vrf = arguments.get('vxlan-avoid-flooding', 'mac-vrf')
    static_vtep = arguments.get('vxlan-avoid-flooding', 'vtep')
    mac = arguments.get('vxlan-avoid-flooding', 'mac')
    logging.info( f"mac-vrf={mac_vrf} static_vtep={static_vtep} mac={mac}" )

    # add to CLI candidate config
    path = f'/network-instance[name={mac_vrf}]/protocols/bgp-evpn/bgp-instance[id=1]/vxlan-agent/static-vtep[vtep-ip={static_vtep}]'
    macs = json.dumps( { "static-macs" : [ mac ] } )
    state.server.set_json(path=build_path(path), value=macs,
                          data_store=DataStore.Candidate, is_replace=False)

    # logging.info( "Cur:" + str(_fetch_existing_leaflist_values(state,build_path(path))) )
    # state.server.update_configuration(paths=inserted_paths)
