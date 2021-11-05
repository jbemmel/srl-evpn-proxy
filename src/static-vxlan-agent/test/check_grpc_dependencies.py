#!/usr/bin/env python
# coding=utf-8

# Small test program to check which grpc files are loaded for eventlet support
# Usage:
# export VIRTUAL_ENV=/opt/static-vxlan-agent/.venv/
# export PATH=${VIRTUAL_ENV}/bin:${PATH}
# PYTHONVERBOSE=2 python3 check_grpc_dependencies.py 2>&1 | grep import

# Google core libraries don't support eventlet; workaround
from grpc.experimental import eventlet as grpc_eventlet

grpc_eventlet.init_eventlet() # Fix gRPC eventlet interworking, early

print( "Test done" )
