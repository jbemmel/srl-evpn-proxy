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

import logging

#
# L2 service ping using custom ARP packets
#
class VxlanServicePing(ToolsPlugin):

    # Provide list of plugins that must be loaded before this one
    def get_required_plugins(self):
        return [RequiredPlugin("tools_mode")]

    # Define where this command exists in the command hierarchy in sr_cli
    def on_tools_load(self, state):
        # Could also add it under /tools network-instance
        root = state.command_tree.tools_mode.root
        root.add_command(self._get_syntax(), update_location=False, callback=do_service_ping)

    # Helper function to get arguments and help strings for this plugin command
    def _get_syntax(self):
        syntax = Syntax("vxlan-service-ping", help="Pings other VXLAN VTEPs in a given L2 overlay service")
        syntax.add_named_argument('mac-vrf', suggestions=KeyCompleter(path='/network-instance[type=mac-vrf]')) # Cannot select type=mac-vrf only?
        syntax.add_unnamed_argument(name='vtep', default='*', suggestions=KeyCompleter(path='/network-instance[type=mac-vrf]')) # Lookup state published by evpn agent

        # TODO add 'count' argument, default 3

# end class VxlanServicePing

    # Callback that runs when the plugin is run in sr_cli
def do_service_ping(state, input, output, arguments, **_kwargs):
    logging.debug( f"JvB: do_service_ping arguments={arguments}" )

    # For each uplink interface in default vrf:
    # 1. Get MAC and peer MAC
    # 2. Pass MACs to agent config
