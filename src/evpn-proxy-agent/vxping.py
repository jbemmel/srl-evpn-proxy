#!/usr/bin/python3

import socket, sys
from datetime import datetime, timezone
from ryu.lib.packet import packet, ipv4, udp, vxlan, ethernet, arp
from ryu.ofproto import ether, inet

if len(sys.argv) < 5:
    print( f"Usage: {sys.argv[0]} <VNI> <local VTEP IP> <list of uplink devices separated by ','> <list of VTEP IPs separated by ','>" )
    sys.exit(1)

VNI = int(sys.argv[1])
LOCAL_VTEP = sys.argv[2]
UPLINKS = sys.argv[3].split(",")
VTEP_IPs = sys.argv[4].split(",")

def get_timestamp_us(): # 40-bit
   now = datetime.now(timezone.utc)
   return int( int(now.timestamp() * 1000000) & 0xffffffffff )

# Build VXLAN ARP packet
RFC5494_EXP1 = 24 # See https://datatracker.ietf.org/doc/html/rfc5494
ZERO = "00:00:00:00:00:00"
vxl = vxlan.vxlan(vni=VNI)
eth = ethernet.ethernet(dst=ZERO,src=ZERO,ethertype=ether.ETH_TYPE_ARP)
a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=RFC5494_EXP1,
            src_mac=ZERO, src_ip=LOCAL_VTEP,
            dst_mac=ZERO, dst_ip="0.0.0.0" )

p = packet.Packet()
for h in [vxl,eth,a]:
   p.add_protocol(h)

def timestamped_packet(path):
    ts = t = get_timestamp_us()
    ts_mac = ""
    for b in range(0,5): # 40 bit
       ts_mac = f":{(t%256):02x}" + ts_mac
       t = t // 256

    a.src_mac = f'{path:1x}1'+ts_mac
    p.serialize()
    return p

for path in range(1,4):
  vxlan_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
  vxlan_sock.bind( (LOCAL_VTEP, 1000*path) ) #  vary source port
  for i in UPLINKS:
    vxlan_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, i.encode() )
    for v in VTEP_IPs:
      a.dst_ip = v
      pkt = timestamped_packet(path)
      print( f"Sending {pkt}" )
      vxlan_sock.sendto( pkt.data, (v,4789) )

sys.exit(0)
