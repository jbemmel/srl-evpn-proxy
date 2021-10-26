#!/usr/bin/python3
#
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#
#eBPF application that parses HTTP packets
#and extracts (and prints on screen) the URL contained in the GET/POST request.
#
#eBPF program http_filter is used as SOCKET_FILTER attached to eth0 interface.
#only packet of type ip and tcp containing HTTP GET/POST are returned to userspace, others dropped
#
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)
#and prints on stdout the first line of the HTTP GET/POST request containing the url

from __future__ import print_function
from bcc import BPF
from sys import argv

import sys
import socket
import os
# import netns

from ryu.lib.packet import packet, vxlan, ethernet, arp

#args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()

#help
def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is enp0s3")
    print("")
    print("examples:")
    print(f"    {argv[0]}              # bind socket to mgmt0.0")
    print(f"    {argv[0]} -i e1-1      # bind socket to e1-1")
    exit()

#arguments
interface="enp0s3"
net_namespace="srbase"

if len(argv) == 2:
  if str(argv[1]) == '-h':
    help()
  else:
    usage()

if len(argv) == 3:
  if str(argv[1]) == '-i':
    interface = argv[2]
  else:
    usage()

if len(argv) > 3:
  usage()

print( f"binding socket to '{interface}' in netns '{net_namespace}'" )

# initialize BPF - load source code from http-parse-simple.c
bpf = BPF(src_file = "filter-tcp-rtt.c",debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_arp_filter = bpf.load_func("tcp_rtt_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
# with netns.NetNS(nsname=net_namespace):
BPF.attach_raw_socket(function_arp_filter, interface)

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_arp_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)

while 1:
    #retrieve raw packet from socket
    packet_str = os.read(socket_fd,2048)

    #DEBUG - print raw packet in hex format
    #packet_hex = toHex(packet_str)
    #print ("%s" % packet_hex)

    #convert packet into bytearray
    packet_bytearray = bytearray(packet_str)

    try:
      pkt = packet.Packet( packet_bytearray )
      for p in pkt:
          if hasattr(p,'protocol_name'):
           print( p.protocol_name, p )
           if p.protocol_name == 'vlan':
              print( f'vlan id = {p.vid}' )
           elif p.protocol_name == 'vxlan':
              print( f'vni = {p.vni}' )

    except AssertionError as e:
      print( f"Not a valid VXLAN packet? {e}" )

    # Debug - requires '/sys/kernel/debug/tracing/trace_pipe' to be mounted
    # (task, pid, cpu, flags, ts, msg) = bpf.trace_fields( nonblocking=True )
    # print( f'trace_fields: {msg}' )
