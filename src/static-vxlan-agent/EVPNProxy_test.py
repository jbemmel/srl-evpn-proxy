import eventlet
import unittest
# import aiounittest # until Python 3.8 is available
import logging
import socket

import sys
import asyncio

# from ryu.lib import hub

# unittest replaces sys.stdout/sys.stderr
logger = logging.getLogger()
logger.level = logging.DEBUG # INFO # DEBUG
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)

from EVPNProxy import EVPNProxy

VNI = 1234
EVI = 57069

MAC1 = "00:11:22:33:44:01"
MAC2 = "00:11:22:33:44:02"

AGENT1 = "1.1.1.4"
AGENT2 = "1.1.1.6"

# Static VTEPs (TODO emulate dynamic EVPN VTEPs too, by calling rxEVPN_RT2)
VTEP1 = "1.1.1.1"
VTEP2 = "1.1.1.2"
VTEP3 = "1.1.1.5" # SRL1
VTEP4 = "1.1.1.7" # SRL2

#
# Run: ip netns exec srbase-default python3 /opt/demo-agents/evpn-proxy-agent/EVPNProxy_test.py
#
# Note that Ryu only supports a single BGPSpeaker per Python process, hence we
# need to create multiple test processes (one per EVPN proxy)
#
# These tests are designed to be run inside the srbase_default namespace on SRL
#
# TODO use unittest.IsolatedAsyncioTestCase (Python 3.8)
#
class EVPNProxyTestCase( unittest.TestCase ): # tried aiounittest.AsyncTestCase

 @classmethod
 def setUpClass(cls):
   logging.info("setUpClass")

   # 8378 == "TEST" on a phone dialpad
   serverAddr = (sys.argv[1],8378) if len(sys.argv)>1 else None

   # Create a TCP/IP socket
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   sock.setblocking( True )
   logger.info( f"Opening socket server={serverAddr}" )
   if serverAddr is None:
       sock.bind( (AGENT1,8378) )
       sock.listen(1)
       cls.clientsock, cls.clientAddr = sock.accept()
       cls.clientsock.setblocking( True )
   else:
       sock.connect( serverAddr )
       cls.clientsock = cls.clientAddr = None
   cls.sock = sock

 @classmethod
 def tearDownClass(cls):
     if cls.clientsock:
         cls.clientsock.close()
     cls.sock.close()

 def syncClientServer(self,msg):
   if self.clientsock:
      sync_msg = self.clientsock.recv( bufsize=256 )
      logging.info( f"Server: sync_msg={sync_msg}, echoing")
      self.clientsock.sendall(sync_msg)
   else:
      logging.info( f"Client: sending sync_msg '{msg}'" )
      msg_bytes = msg.encode()
      self.sock.sendall(msg_bytes)
      sync_msg = self.sock.recv( bufsize=256 )
      logging.info( f"Client: received sync_msg {sync_msg}" )
      self.assertEqual( sync_msg, msg_bytes, "Sync failed" )

 def setUp(self):
   logging.info( "setUp" )

   # Restore our log
   stream_handler.stream = sys.stdout

   # Synchronize client/server
   self.syncClientServer("setUp")

   self.evpn_proxy = EVPNProxy(router_id=AGENT1 if self.clientAddr else AGENT2)

   # Assumes a BGP neighbor config in SRL
   # Cannot 'await'
   self.evpn_proxy.connectBGP_EVPN() # TODO wait for connect event

   eventlet.sleep(8)

   self.assertTrue( self.evpn_proxy.isEVPNVTEP(VTEP3),
     f"Proxy failed to detect EVPN VTEP {VTEP3}" )

   # Requires VTEP3/VTEP4 to be peered AND VTEP3 as Route Reflector
   self.assertTrue( self.evpn_proxy.isEVPNVTEP(VTEP4),
     f"Proxy failed to detect EVPN VTEP {VTEP4}" )

   self.evpn_proxy.addStaticVTEP( VNI, EVI, VTEP1 )
   self.evpn_proxy.addStaticVTEP( VNI, EVI, VTEP2 )

 def tearDown(self):
   logging.info( "TEARDOWN - sync, then shutdown EVPN proxy" )
   self.syncClientServer("tearDown")
   self.evpn_proxy.shutdown()
   eventlet.sleep(1)

 def assertRoute(self,vni,mac,vtep_ip,src=None):
   route = self.evpn_proxy.checkAdvertisedRoute(vni,mac)
   self.assertIsNotNone( route, f"No EVPN route advertised for {vni} {mac}" )
   self.assertTrue( 'vtep' in route, "No 'vtep' in route" )
   self.assertEqual( route['vtep'], vtep_ip,
     f"proxy failed to advertise correct VTEP IP {vtep_ip}" )
   if src:
      self.assertTrue( 'src' in route, "No 'src' in route" )
      self.assertEqual( route['src'], src, "Unexpected source" )

 def assertNoRoute(self,vni,mac):
   route = self.evpn_proxy.checkAdvertisedRoute(vni,mac)
   self.assertIsNone( route, f"proxy failed to withdraw route for {vni} {mac}" )

 def test_1_normal_scenario_arp_request_broadcast(self,src=VTEP1,dst=VTEP3):
   # ARP request broadcast to all proxies
   self.evpn_proxy.rxVXLAN_ARP( VNI, src, dst, MAC1 )
   eventlet.sleep(1)

   self.assertRoute( VNI, MAC1, src, src='arp' )

 # Case: ARP response sent from static VTEP (or lost ARP broadcast request)
 def test_2_normal_scenario_arp_response_unicast(self,src=VTEP1,dst=VTEP3):
   # ARP response received by proxy AGENT1 on VTEP3
   if self.clientsock:
      self.evpn_proxy.rxVXLAN_ARP( VNI, src, dst, MAC1 )
   eventlet.sleep(2)

   # The other proxy AGENT2 should receive the route from AGENT1 via EVPN
   self.assertRoute( VNI, MAC1, src, src='arp' if self.clientsock else 'evpn' )

 # Case: MAC move static VTEP1 to static VTEP2
 def test_3_normal_scenario_mac_move(self):
   self.test_1_normal_scenario_arp_request_broadcast(src=VTEP1,dst=VTEP3)

   # Emulate MAC1 moving to static VTEP2
   self.test_1_normal_scenario_arp_request_broadcast(src=VTEP2,dst=VTEP3)

 # Case: MAC move static VTEP1 to EVPN VTEP4
 def test_4_normal_scenario_mac_move_to_evpn(self):
   self.test_1_normal_scenario_arp_request_broadcast(src=VTEP1,dst=VTEP3)

   # Emulate MAC1 moving to EVPN VTEP4, detected via ARP
   self.evpn_proxy.rxVXLAN_ARP( VNI, VTEP4, VTEP3, MAC1 )
   eventlet.sleep(1)

   self.assertNoRoute( VNI, MAC1 )

 # Case: MAC move static VTEP1 to EVPN VTEP4, detected through RT2 update
 def test_5_normal_scenario_mac_move_to_evpn_detected_via_evpn(self):
   self.test_1_normal_scenario_arp_request_broadcast(src=VTEP1,dst=VTEP3)

   # Emulate MAC1 moving to EVPN VTEP4, seen via RT2
   self.evpn_proxy.rxEVPN_RT2( VNI, MAC1, VTEP4, is_from_proxy=False )
   eventlet.sleep(1)

   self.assertNoRoute( VNI, MAC1 )

if __name__ == '__main__':
   # unittest.main( argv=sys.argv[:1] )  # Only pass program name
   unittest.main( argv=[ sys.argv[0], '-v',
     'EVPNProxyTestCase.test_2_normal_scenario_arp_response_unicast' ] )
