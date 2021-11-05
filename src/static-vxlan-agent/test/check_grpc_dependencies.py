#!/usr/bin/env python
# coding=utf-8

# Small test program to check which grpc files are loaded for eventlet support
# Usage:
# source /opt/static-vxlan-agent/.venv/bin/activate
# PYTHONVERBOSE=2 python3 check_grpc_dependencies.py 2>&1 | grep import

# Google core libraries don't support eventlet; workaround
from grpc.experimental import eventlet as grpc_eventlet

grpc_eventlet.init_eventlet() # Fix gRPC eventlet interworking, early

print( "Test done" )
