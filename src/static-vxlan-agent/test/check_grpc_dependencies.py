#!/usr/bin/env python
# coding=utf-8

# Small test program to check which grpc files are loaded for eventlet support
# Usage:
# export VIRTUAL_ENV=/opt/static-vxlan-agent/.venv/
# export PATH=${VIRTUAL_ENV}/bin:${PATH}
# PYTHONVERBOSE=2 python3 check_grpc_dependencies.py 2>&1 | awk '/grpc/ { print $4 }'

# Google core libraries don't support eventlet; workaround
from grpc.experimental import eventlet as grpc_eventlet

grpc_eventlet.init_eventlet() # Fix gRPC eventlet interworking, early

print( "Test done" )

# [linuxadmin@srl1 test]$ PYTHONVERBOSE=2 python3 check_grpc_dependencies.py 2>&1 | grep match | grep grpc
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/__pycache__/__init__.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/__init__.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/__pycache__/_compression.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_compression.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_cython/__pycache__/__init__.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_cython/__init__.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/__pycache__/_runtime_protos.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_runtime_protos.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/__pycache__/_grpcio_metadata.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_grpcio_metadata.py
# /usr/local/lib64/python3.6/site-packages/grpc_tools/__pycache__/__init__.cpython-36.pyc matches /usr/local/lib64/python3.6/site-packages/grpc_tools/__init__.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/__init__.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__init__.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_base_call.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_base_call.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_metadata.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_metadata.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_typing.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_typing.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_base_channel.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_base_channel.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_base_server.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_base_server.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_call.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_call.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/__pycache__/_common.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_common.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_channel.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_channel.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_interceptor.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_interceptor.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_utils.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_utils.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/__pycache__/_server.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/aio/_server.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/experimental/__pycache__/__init__.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/experimental/__init__.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/__pycache__/_simple_stubs.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/_simple_stubs.py
# /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/experimental/__pycache__/eventlet.cpython-36.pyc matches /opt/static-vxlan-agent/.venv/lib/python3.6/site-packages/grpc/experimental/eventlet.py
