#!/bin/bash
###########################################################################
# Description:
#     This script will launch the python script of the EVPN proxy agent
#     (forwarding any arguments passed to this script).
#
# Copyright (c) 2018-2021 Nokia, generated by srl-agent-builder
###########################################################################


_term (){
    echo "Caugth signal SIGTERM !! "
    kill -TERM "$child" 2>/dev/null
}

function main()
{
    trap _term SIGTERM
    local virtual_env="/opt/static-vxlan-agent/.venv/bin/activate"
    local main_module="/opt/static-vxlan-agent/evpn-proxy-agent.py"

    # source the virtual-environment, which is used to ensure the correct python packages are installed,
    # and the correct python version is used
    source "${virtual_env}"

    # Include local paths where custom packages are installed
    #P1="/usr/local/lib/python3.6/site-packages"
    #P2="/usr/local/lib64/python3.6/site-packages"
    #P3="/usr/lib/python3.6/site-packages"
    #P4="/usr/lib64/python3.6/site-packages"
    # SRL_VENV="/opt/srlinux/python/virtual-env/lib/python3.6/site-packages"
    # since 21.6
    SDKPATH="/usr/lib/python3.6/site-packages/sdk_protos"
    export PYTHONPATH="$SDKPATH:$PYTHONPATH"

    # Opening srbase-default namespace requires root
    python3 ${main_module} &

    child=$!
    wait "$child"
}

main "$@"
