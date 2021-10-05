#!/usr/bin/python3

#
# Assumes this is being run in srbase-default namespace (however its name)
#

import socket, sys, re, os, netns, selectors, logging, ipaddress
from datetime import datetime, timezone
from ryu.lib.packet import packet, ipv4, udp, vxlan, ethernet, arp
from ryu.ofproto import ether, inet

# from bcc import BPF
from bcc.libbcc import lib

if len(sys.argv) < 5:
    print( f"Usage: {sys.argv[0]} <VNI> <local VTEP IP> <list of uplink devices separated by ','> <list of VTEP IPs separated by ','> [optional source ip/prefix for ping sweep]" )
    sys.exit(1)

VNI = int(sys.argv[1])
LOCAL_VTEP = sys.argv[2]
UPLINKS = sys.argv[3].split(",")
VTEP_IPs = sys.argv[4].split(",")
SUBNET_SRC = sys.argv[5] if len(sys.argv) > 5 else None

DEBUG = 'DEBUG' in os.environ and bool( os.environ['DEBUG'] )
logging.basicConfig(
  filename='/var/log/srlinux/stdout/vxping.log',
  format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
  datefmt='%H:%M:%S',
  level=logging.DEBUG if DEBUG else logging.INFO)

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
a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=RFC5494_EXP1,
            src_mac=ZERO, src_ip=LOCAL_VTEP,
            dst_mac=ZERO, dst_ip="0.0.0.0" )

p = packet.Packet()
for h in [e,ip,u,vxl,e2,a]:
   p.add_protocol(h)

def timestamped_packet(path):
    ts = t = get_timestamp_us()
    ts_mac = ""
    for b in range(0,5): # 40 bit
       ts_mac = f":{(t%256):02x}" + ts_mac
       t = t // 256
    ip.identification = path
    u.src_port = path * 1000
    u.csum = 0 # Recalculate
    a.src_mac = f'{path:1x}1'+ts_mac
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
        logging.debug( f'Received {len(data)} bytes on {intf}' )
        # Our ARP packets are 110 bytes
        if len(data)==110:
           pkt = packet.Packet( bytearray(data) )
           _arp = pkt.get_protocol( arp.arp )
           if _arp.opcode != RFC5494_EXP1:
               return
           _ip = pkt.get_protocol( ipv4.ipv4 )
           logging.debug( pkt )

           path = int(_arp.src_mac[0],16)
           phase = int(_arp.src_mac[1],16) + 1
           ttl = int( _arp.dst_mac[0:2], 16 ) # Starts as 255

           m = [ int(b,16) for b in _arp.src_mac[3:].split(':') ]
           ts = (m[0]<<32)+(m[1]<<24)+(m[2]<<16)+(m[3]<<8)+m[4]
           delta = get_timestamp_us() - ts
           if (delta<0):
               delta += (1<<40)
           logging.debug( f"Received reflected ARP probe (TS={ts} delta={delta} path={path} phase={phase}), ARP={_arp} intf={intf}" )

           print( f"Ping response from {_ip.src} on interface {sock.getsockname()[0]}: RTT={delta} us hops={255-ttl}" )
           ping_replies.append( { 'hops': 255-ttl, 'hops-return': 255 - _ip.ttl,
                                  'rtt': delta, 'interface': intf } )
           return True

    return False

# If a subnet ip/src is provided, perform a ping sweep (receiving on all uplinks)
if SUBNET_SRC:
   print( f"Performing subnet ARP sweep from IP={SUBNET_SRC}...")
   subnet = ipaddress.ip_network(SUBNET_SRC,strict=False)
   src = SUBNET_SRC.split('/')[0]
   hosts = list( map( str, subnet.hosts() ) )
   hosts.pop( src, None )

   e2.dst_mac = 'ff:ff:ff:ff:ff:ff'
   a.opcode = 1 # Request
   a.src_mac = 'da:da:' + ":".join( [ f'{int(b):02x}' for b in src.split('.') ] ) # pick consistent unique value
   a.src_ip = src

for c,i in enumerate(UPLINKS):
    uplink_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    e.src = e2.src = get_interface_mac(uplink_sock, i)
    e.dst = e2.dst = get_peer_mac(uplink_sock, i)
    uplink_sock.close()

    base_intf = i.split('.')[0] # e1-1.0 -> e1-1 in srbase

    # Use BCC bpf_open_raw_sock to create a raw socket attached in srbase netns
    with netns.NetNS(nsname="srbase"):
       socket_fd = lib.bpf_open_raw_sock(base_intf.encode())

    vxlan_sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
    # vxlan_sock.setblocking(True)
    vxlan_sock.setblocking(False)
    sel.register(vxlan_sock, selectors.EVENT_READ, receive_packet)

    if SUBNET_SRC:
       for c2,host_ip in enumerate(hosts):
           # Spread across all uplinks
           if c2%len(UPLINKS) == c:
               a.dst_ip = host_ip
               p.serialize()
               print( f"Sending ARP to {host_ip} on uplink {i}: {p}" )
               vxlan_sock.sendall( p.data )
               pings_sent += 1
    else:
       for v in VTEP_IPs:
          ip.dst = v
          a.dst_ip = v
          for path in range(1,4):
             pkt = timestamped_packet(path)
             logging.debug( f"Sending {pkt}" )
             print( f"Sending ARP ping packet #{path} to {v} on {i}" )
             vxlan_sock.sendall( pkt.data )
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
logging.debug( ping_replies )
for i in UPLINKS:
  rtts = [ r['rtt'] for r in ping_replies if r['interface'] in i ]
  if len(rtts)>0:
     # align right 8, whole division
     print( f"Average RTT received on interface {i} over {len(rtts)} packets: {sum(rtts)//len(rtts):>8} us" )
  else:
     print( f"No replies received on interface {i}" )

sys.exit(0)
