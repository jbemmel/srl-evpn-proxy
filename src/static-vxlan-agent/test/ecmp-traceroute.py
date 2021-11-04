#!/usr/bin/python3

#
# UDP traceroute utility to check reachability and measure RTT between routers
# (e.g. VXLAN VTEP loopback IPs) across all uplinks and available paths
#
# Sends out UDP packets with destination ports in the range 33434-33464
# (as allowed by SR Linux in the default config). The port is incremented for
# every next hop (max TTL=n), and for every packet to that next hop (probes-per-hop=3)
#
# Assumes this is being run in srbase-default namespace (however its name)
#
# See also: https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/traceroute/index.html
#

import socket, sys, re, os, netns, selectors, logging, ipaddress
from datetime import datetime, timezone
from ryu.lib.packet import packet, ipv4, udp, vxlan, ethernet, arp, icmp, icmpv6
from ryu.ofproto import ether, inet

# from bcc import BPF
from bcc.libbcc import lib

if len(sys.argv) < 5:
    print( f"Usage: {sys.argv[0]} <local VTEP IP> <entropy> <list of uplink devices separated by ','> <list of VTEP IPs separated by ','>" )
    sys.exit(1)

LOCAL_VTEP = sys.argv[1]
ENTROPY = int(sys.argv[2])
UPLINKS = sys.argv[3].split(",")
VTEP_IPs = sys.argv[4].split(",")

DEBUG = 'DEBUG' in os.environ and bool( os.environ['DEBUG'] )
SRL_C = os.path.exists('/.dockerenv')
logging.basicConfig(
  filename='/var/log/srlinux/stdout/ecmp-traceroute.log',
  format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
  datefmt='%H:%M:%S',
  level=logging.DEBUG if DEBUG else logging.INFO)

logging.info( f"Command: {sys.argv}" )
print( f"Containerized SRL:{SRL_C}" )

def get_timestamp_us(): # 40-bit
   now = datetime.now(timezone.utc)
   return int( int(now.timestamp() * 1000000) & 0xffffffffff )

# Build UDP traceroute packet
IANA_UDP_PORT = 33434
ZERO = "00:00:00:00:00:00"

e = ethernet.ethernet(dst=ZERO, # nexthop MAC, per vxlan_intf
                      src=ZERO, # source interface MAC, per uplink
                      ethertype=ether.ETH_TYPE_IP)
ip = ipv4.ipv4(dst=VTEP_IPs[0],src=LOCAL_VTEP,proto=inet.IPPROTO_UDP,
              tos=0xc0,identification=0,flags=(1<<1)) # Set DF
u = udp.udp(src_port=0,dst_port=IANA_UDP_PORT) # vary source == timestamp

# TODO proper payload
p = packet.Packet(protocols=[e,ip,u,"<timestamp>"])

# For containerized SRL, hashing only considers the src IP address
# Include entropy in src IP 2nd octet, and correct it (based on ID) in reply
def ip_with_entropy(ip,entropy):
    digits = [ int(i) for i in ip.split('.') ]
    digits[1] ^= (entropy) % 256
    return ".".join( map(str,digits) )

def prepare_packet(path,ttl):
    #if timestamp:
    #   ts = t = get_timestamp_us()
    #   ts_mac = ""
    #   for b in range(0,5): # 40 bit
    #      ts_mac = f":{(t%256):02x}" + ts_mac
    #      t = t // 256
    #   a.src_mac = f'{path%10:1x}2'+ts_mac  # 2 == Locally administered, unicast

    # ip.src = LOCAL_VTEP
    ip.identification = path + ENTROPY
    ip.ttl = ttl
    u.dst_port = IANA_UDP_PORT + ttl*path - 1
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
    """
    Uses 'arping' command to get peer MAC address on given uplink
    """
    local_ip = get_interface_ip(sock,uplink)
    d = int(local_ip[-1])
    peer_ip = local_ip[:-1] + str( (d-1) if (d%2) else (d+1) )
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

        _icmp = pkt.get_protocol( icmp.icmp )
        if not _icmp:
            print( f"Ignoring non-ICMPv4 packet on {intf}: {pkt}" )
            return False
        _ip = pkt.get_protocols( ipv4.ipv4 )
        logging.debug( f"Received ICMP reply on intf={intf}: {pkt}" )
        print( f"ICMP reply from IP {_ip[1].src} VTEP={_ip[0].src} to IP {_ip[1].dst} VTEP={_ip[0].dst} on interface {intf} : {pkt}" )
        return True

    return False

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
   trace_sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
   # trace_sock.setblocking(True)
   trace_sock.setblocking(False)
   sel.register(trace_sock, selectors.EVENT_READ, receive_packet)
   uplink_sockets[i] = { 'sock': trace_sock, 'src_mac': src_mac, 'dst_mac': dst_mac }

# Then send packets in TTL bursts; wait between each cycle
for n in range(0,1): # Repeat 1 times
 for ttl in range(1,3):
  for c,i in enumerate(UPLINKS):
    sock = uplink_sockets[i]
    e.src = sock['src_mac']
    e.dst = sock['dst_mac']

    for v in VTEP_IPs:
       ip.dst = v
       for path in range(0,3):
          pkt = prepare_packet( c*4+path, ttl )
          logging.debug( f"Sending {pkt}" )
          print( f"Sending UDP traceroute #{n}.{path} TTL={ttl} to {v} on {i}: {pkt}" )
          sock['sock'].sendall( pkt.data )
          pings_sent += 1
          # bytes_sent = vxlan_sock.sendto( pkt.data, (v,0) )
          # print( f"Result: {bytes_sent} bytes sent" )

  # TODO continue immediately when ICMP responses are in for all
  print( f"Waiting for ICMP responses TTL={ttl}..." )
  time.sleep( 1 )

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
