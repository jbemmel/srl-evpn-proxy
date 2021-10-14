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
from srlinux.schema import DataStore

import sys
import logging
import json
import requests

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
        syntax.add_named_argument('vtep',help="Target static VTEP where MAC resides",
           suggestions=KeyCompleter(path=_get_vteps_in_vrf,data_store=DataStore.Running) )

        #def _get_learnt_macs_in_vrf(arguments):
        #   mac_vrf = arguments.get_or('mac-vrf','*')
           # logging.info( f"_get_learnt_macs_in_vrf args={arguments} mac_vrf={mac_vrf}" )
        #   return build_path(f'/network-instance[name={mac_vrf}]/bridge-table/mac-learning/learnt-entries/mac[address=*]')

        syntax.add_named_argument('cumulus_user', default="root", help="API user to retrieve MACs from Cumulus")
        syntax.add_named_argument('cumulus_password', default="root", help="API password to retrieve MACs from Cumulus")

        # ip netns exec srbase-default ssh root@1.1.1.1 'net show bridge macs' | awk '/bridge  e1/ { print $4 }' | uniq
        syntax.add_named_argument('mac', help="Dynamic MAC to associate with static VTEP",
           suggestions=CumulusMACCompleter() )

        syntax.add_boolean_argument('refresh', help="Force refresh of API query for MACs")

        return syntax

# end class VxlanAvoidFlooding

from typing import Iterator, List, Optional
from srlinux.mgmt.cli.command_node_with_arguments import CommandNodeWithArguments
from srlinux.syntax.argument import Argument
from . import cumulus

class CumulusMACCompleter(object):
    '''
        Provides auto-completion options for dynamic MACs retrieved from Cumulus
        "REST API" (RPC call producing CLI output)

        Requires: sudo systemctl enable restserver && systemctl start restserver (on Cumulus)
    '''

    def __init__(self, limit: Optional[int] = None):
        self._limit = limit or 50
        self._macs = {} # Cache query per VTEP

    def __call__(self, syntax_argument: Argument, state: 'CliState', arguments: CommandNodeWithArguments,
                 partial_word: str, line: str) -> Iterator[str]:
        logging.debug( f"CumulusMACCompleter: partial_word={partial_word} line={line}" )
        vtep = arguments.get('vtep')
        refresh = arguments.get_or('refresh', False)
        if vtep not in self._macs or refresh:
          user = arguments.get('cumulus_user')
          pswd = arguments.get('cumulus_password')
          try:
             self._macs[ vtep ] = cumulus.retrieve_dynamic_MACs( vtep, user, pswd )
          except Exception as err:
             self._macs[ vtep ] = [ "< error retrieving MACs - REST API enabled and using correct credentials? >" ]

        result: List[str] = [ m for m in self._macs[vtep] if m.startswith(partial_word) ]
        return iter(  result[ :self._limit ] )

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
