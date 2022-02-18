#!/usr/bin/python3

#
# Assumes this is being run in srbase-default namespace (however its name)
#

import socket, sys, re, os, netns, selectors, logging, ipaddress
from datetime import datetime, timezone
from ryu.lib.packet import packet, ipv4, udp, vxlan, ethernet, arp, icmp, icmpv6
from ryu.ofproto import ether, inet

# from bcc import BPF
from bcc.libbcc import lib

if len(sys.argv) < 7:
    print( f"Usage: {sys.argv[0]} <proto> <VNI> <local VTEP IP> <entropy> <list of uplink devices separated by ','> <list of VTEP IPs separated by ','> [optional dest IP and source MAC/IP for ping]" )
    sys.exit(1)

PROTO = sys.argv[1] # arp or icmp or icmpv6
VNI = int(sys.argv[2])
LOCAL_VTEP = sys.argv[3]
ENTROPY = int(sys.argv[4])
UPLINKS = sys.argv[5].split(",")
VTEP_IPs = sys.argv[6].split(",")

PING_DST = sys.argv[7] if len(sys.argv) > 7 else ""
PING_SRC_MAC = sys.argv[8] if len(sys.argv) > 8 else None
PING_SRC_IP = sys.argv[9] if len(sys.argv) > 9 else None

DEBUG = 'DEBUG' in os.environ and bool( os.environ['DEBUG'] )
SRL_C = os.path.exists('/.dockerenv')
logging.basicConfig(
  filename='/var/log/srlinux/stdout/vxping.log',
  format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
  datefmt='%H:%M:%S',
  level=logging.DEBUG if DEBUG else logging.INFO)

logging.info( f"Command: {sys.argv}" )
print( f"Containerized SRL:{SRL_C}" )

def get_timestamp_us(): # 40-bit
   now = datetime.now(timezone.utc)
   return int( int(now.timestamp() * 1000000) & 0xffffffffff )

# Build VXLAN ARP packet
RFC5494_EXP1 = 24 # See https://datatracker.ietf.org/doc/html/rfc5494
ZERO = "00:00:00:00:00:00"

e = ethernet.ethernet(dst=ZERO, # nexthop MAC, per vxlan_intf
                      src=ZERO, # source interface MAC, per uplink
                      ethertype=ether.ETH_TYPE_IP)
ip = ipv4.ipv4(dst=VTEP_IPs[0],src=LOCAL_VTEP,proto=inet.IPPROTO_UDP,
              tos=0xc0,identification=0,flags=(1<<1)) # Set DF
u = udp.udp(src_port=0,dst_port=4789) # vary source == timestamp
vxl = vxlan.vxlan(vni=VNI)
e2 = ethernet.ethernet(dst=ZERO,src=ZERO,ethertype=ether.ETH_TYPE_ARP)
e2._MIN_PAYLOAD_LEN = 0 # Avoid padding
a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=RFC5494_EXP1,
            src_mac=ZERO, src_ip=LOCAL_VTEP,
            dst_mac=ZERO, dst_ip="0.0.0.0" )
ip2 = ipv4.ipv4(proto=inet.IPPROTO_ICMP,tos=0xc0,identification=0)
payload = [a]
if PROTO=="icmp":
  e2.ethertype = ether.ETH_TYPE_IP
  ping = icmp.icmp( data=icmp.echo(id_=1,seq=0x1234) ) # TODO data=timestamp
  payload = [ip2,ping]

p = packet.Packet()
for h in [e,ip,u,vxl,e2]+payload:
   p.add_protocol(h)

# For containerized SRL, hashing only considers the src IP address
# Include entropy in src IP 2nd octet, and correct it (based on ID) in reply
def ip_with_entropy(ip,entropy):
    digits = [ int(i) for i in ip.split('.') ]
    digits[1] ^= (entropy) % 256
    return ".".join( map(str,digits) )

def prepare_packet(path,timestamp=True):
    if timestamp:
       ts = t = get_timestamp_us()
       ts_mac = ""
       for b in range(0,5): # 40 bit
          ts_mac = f":{(t%256):02x}" + ts_mac
          t = t // 256
       a.src_mac = f'{path%10:1x}2'+ts_mac  # 2 == Locally administered, unicast
       #if set_inner_src:
       #   e2.src = a.src_mac

    ip.src = ip_with_entropy( LOCAL_VTEP, path + ENTROPY ) if PROTO=="arp" else LOCAL_VTEP

    ip.identification = path + ENTROPY
    u.src_port = 49152 + (path + ENTROPY) % (65536-49152) # RFC6335 suggested range 49152-65535
    u.csum = 0 # Recalculate, should be 0 (disabled) for VXLAN
    p.serialize()
    return p

def get_interface_ip(sock,dev):
    # ip a show dev e1-1.0 | awk '/inet /{ print $2}'
    # or use ipdb
    import fcntl, struct
    return socket.inet_ntoa(fcntl.ioctl(
        sock.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', dev[:15].encode())
    )[20:24])

def get_interface_mac(sock,dev):
    # ip a show dev e1-1.0 | awk '/inet /{ print $2}'
    # or use ipdb
    # or open('/sys/class/net/'+interface+'/address').readline()
    import fcntl, struct
    info = fcntl.ioctl(
        sock.fileno(),
        0x8927,  # SIOCGIFHWADDR = 0x8927
        struct.pack('256s', dev[:15].encode()))
    return ':'.join(['%02x' % b for b in info[18:24]])

def get_peer_mac(sock,uplink):
    local_ip = get_interface_ip(sock,uplink)
    d = int(local_ip[-1])
    peer_ip = local_ip[:-1] + str( (d-1) if (d%2) else (d+1) )
    # XXX hardcoded name of 'default' network-instance
    # arping = os.popen(f'/usr/sbin/ip netns exec srbase-default /usr/sbin/arping -I {uplink} {peer_ip} -f').read()
    arping = os.popen(f'/usr/sbin/arping -I {uplink} {peer_ip} -f').read()
    print( f"arping: {arping}" )
    mac = re.search( '.*\[([0-9a-fA-F:]+)\].*', arping )
    return mac.groups()[0].lower() if mac else None


sel = selectors.DefaultSelector()
pings_sent = 0
ping_replies = []
def receive_packet(sock, mask):
    data = sock.recv(1000)  # Should be ready
    if data:
        intf = sock.getsockname()[0]
        # print( f'Received {len(data)} bytes on {intf}' )
        pkt = packet.Packet( bytearray(data) )

        # Filter for VXLAN in current VNI
        _vxlan = pkt.get_protocol( vxlan.vxlan )
        if not _vxlan:
            print( f"Ignoring non-VXLAN packet len={len(data)} bytes" )
            return
        elif _vxlan.vni != VNI:
            print( f"Ignoring VXLAN packet with different VNI than {VNI}: {_vxlan.vni}" )
            return

        if PROTO=="icmp":
           _icmp = pkt.get_protocol( icmp.icmp )
           if not _icmp:
               print( f"Ignoring non-ICMPv4 packet on {intf}: {pkt}" )
               return
           _ip = pkt.get_protocols( ipv4.ipv4 )
           _udp = pkt.get_protocol( udp.udp )
           logging.debug( f"Received ICMP reply on intf={intf}: {pkt}" )
           print( f"ICMP reply from IP {_ip[1].src} VTEP={_ip[0].src} to IP {_ip[1].dst} VTEP={_ip[0].dst} on interface {intf} (UDP src={_udp.src_port}): {pkt}" )

        # Our ARP-in-VXLAN packets are 92 bytes
        elif len(data)==92:
           _arp = pkt.get_protocol( arp.arp )
           if not _arp:
              print( f"Ignoring non-ARP packet: {pkt}" )
              return # ignore requests
           elif _arp.opcode == 1:
              print( f"Ignoring ARP request: {pkt}" )
              return # ignore requests
           logging.debug( pkt )

           # Starts as 255
           ttl = int( _arp.dst_mac[0:2], 16 ) if _arp.opcode == RFC5494_EXP1 else 0

           path = int(_arp.src_mac[0],16)
           phase = int(_arp.src_mac[1],16) + 1
           m = [ int(b,16) for b in _arp.src_mac[3:].split(':') ]
           ts = (m[0]<<32)+(m[1]<<24)+(m[2]<<16)+(m[3]<<8)+m[4]
           delta = get_timestamp_us() - ts
           if (delta<0):
              delta += (1<<40)
           logging.debug( f"Received reflected ARP probe (TS={ts} delta={delta} path={path} phase={phase}), ARP={_arp} intf={intf}" )

           hops = (255-ttl) if ttl!=0 else "?"
           _ip = pkt.get_protocol( ipv4.ipv4 )
           _eths = pkt.get_protocols( ethernet.ethernet )

           if _arp.opcode==24:
             src_ip = ip_with_entropy( _ip.src, _ip.identification )
             print( f"ARP(opcode={_arp.opcode}) from {src_ip} to {_ip.dst} id={_ip.identification:04d} on interface {sock.getsockname()[0]} remote uplink MAC {_eths[1].src}: RTT={delta:>8} us hops={hops}" )
             ping_replies.append( { 'hops': hops, 'hops-return': 255 - _ip.ttl,
                                    'rtt': delta, 'interface': intf } )
           else:
             print( f"ARP reply from VTEP={_ip.src} to {_ip.dst} for {_arp.dst_ip} on interface {sock.getsockname()[0]} resolved MAC: {_arp.src_ip}={_eths[1].src}" )
           return True

    return False

# If a subnet ip/src is provided, perform a ping sweep (receiving on all uplinks)
if PING_DST:
   print( f"Performing ping (/sweep) using ARP from/to IP={PING_DST}...")
   if '/' in PING_DST:
      subnet = ipaddress.ip_network(PING_DST,strict=False)
      src = PING_DST.split('/')[0]
      hosts = list( map( str, subnet.hosts() ) )
      if src in hosts:
          hosts.remove( src )
      else:
          print( f"WARNING: Source IP {src} is not a valid host address, YMMV" )
   else:
      # ARP with dst=src does not work
      src = PING_SRC_IP if PING_SRC_IP else str( ipaddress.ip_address( PING_DST ) - 1 )
      hosts = [ PING_DST ]

   e2.src = PING_SRC_MAC
   e2.dst = 'ff:ff:ff:ff:ff:ff' # Ping to broadcast MAC works too!
   a.opcode = arp.ARP_REQUEST # Request
   a.src_mac = PING_SRC_MAC
   a.src_ip = src
   ip2.src = src

# First determine MACs and create listening sockets on all uplinks
uplink_sockets = {}
for i in UPLINKS:
   uplink_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
   src_mac = get_interface_mac(uplink_sock, i)
   dst_mac = get_peer_mac(uplink_sock, i)
   uplink_sock.close()

   base_intf = i.split('.')[0] # e1-1.0 -> e1-1 in srbase

   # Use BCC bpf_open_raw_sock to create a raw socket attached in srbase netns
   with netns.NetNS(nsname="srbase"):
      socket_fd = lib.bpf_open_raw_sock(base_intf.encode()) # This binds socket
   vxlan_sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
   # vxlan_sock.setblocking(True)
   vxlan_sock.setblocking(False)
   sel.register(vxlan_sock, selectors.EVENT_READ, receive_packet)
   uplink_sockets[i] = { 'sock': vxlan_sock, 'src_mac': src_mac, 'dst_mac': dst_mac }

# Then send packets
for n in range(0,1): # Repeat 1 times
  for c,i in enumerate(UPLINKS):
    sock = uplink_sockets[i]
    e.src = sock['src_mac']
    e.dst = sock['dst_mac']

    if PING_DST:
      for v in VTEP_IPs:
       ip.dst = v
       for c2,host_ip in enumerate(hosts):
           # Spread across all uplinks
           if c2%len(UPLINKS) == c or len(hosts)==1:
               a.dst_ip = ip2.dst = host_ip
               pkt = prepare_packet(path=100*n+c2+1,timestamp=False)
               print( f"Sending {PROTO} request for {host_ip} to VTEP {v} on uplink {i}: {pkt}" ) # {pkt}
               sock['sock'].sendall( pkt.data )
               pings_sent += 1
    else:
       e2.src = e.src # Set source MAC of inner packet to outer packet
       for v in VTEP_IPs:
          ip.dst = v
          a.dst_ip = ip2.dst = v
          for path in range(1,4):
             pkt = prepare_packet(c*100 + 10*n + path)
             logging.debug( f"Sending {pkt}" )
             print( f"Sending {PROTO} special ping packet #{n}.{path} to {v} on {i}: {pkt}" )
             sock['sock'].sendall( pkt.data )
             pings_sent += 1
             # bytes_sent = vxlan_sock.sendto( pkt.data, (v,0) )
             # print( f"Result: {bytes_sent} bytes sent" )

    # vxlan_sock.close()

# Listen for packets, with timeout
# Some VTEPs may never respond
# while pings_sent > len(ping_replies):
ts_start = datetime.now().timestamp()
logging.debug( f"Timestamp at start: {ts_start}" )
while True:
    events = sel.select(timeout=1) # 1 second

    # Regular systems don't have uplinks quiet for a full second
    if events==[] or ((datetime.now().timestamp()-ts_start) >= 1.0):
        logging.debug( f"Stop listening after ~1-2s, ping replies={len(ping_replies)}" )
        break
    logging.debug( events )
    for key, mask in events:
        callback = key.data
        callback(key.fileobj, mask)

sel.close()
for s in uplink_sockets.values():
    s['sock'].close()

logging.debug( ping_replies )
if len(ping_replies)>0:
 for i in UPLINKS:
  # Exclude copies of own packets
  rtts = [ r['rtt'] for r in ping_replies if r['interface'] in i and r['hops']!='?' ]
  if len(rtts)>0:
     # align right 8, whole division
     print( f"Average RTT received on interface {i} over {len(rtts)} packets: {sum(rtts)//len(rtts):>8} us" )
  else:
     print( f"No RTT replies received on interface {i}" )

sys.exit(0)
