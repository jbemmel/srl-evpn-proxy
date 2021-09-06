import eventlet
import unittest
import aiounittest # until Python 3.8 is available
import logging
import sys
import asyncio

from ryu.lib import hub

# unittest replaces sys.stdout/sys.stderr
logger = logging.getLogger()
logger.level = logging.INFO # DEBUG
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)

from EVPNProxy import EVPNProxy

VNI = 1234
EVI = 57069

MAC1 = "00:11:22:33:44:01"
MAC2 = "00:11:22:33:44:02"

# Static VTEPs (TODO emulate dynamic EVPN VTEPs too, by calling rxEVPN_RT2)
VTEP1 = "1.1.1.1"
VTEP2 = "1.1.1.2"
VTEP3 = "1.1.1.5" # SRL1
VTEP4 = "1.1.1.7" # SRL2

#
# Run: cd /opt/srlinux/agents/evpn-proxy-agent && ip netns exec srbase-default python3 -m unittest EVPNProxy_test.EVPNProxyTestCase -v
#
# Note that Ryu only supports a single BGPSpeaker per Python process, hence we
# need to create multiple test processes (one per EVPN proxy)
#
# These tests are designed to be run inside the srbase_default namespace on SRL
#
# TODO use unittest.IsolatedAsyncioTestCase (Python 3.8)
#
class EVPNProxyTestCase( unittest.TestCase ): # tried aiounittest.AsyncTestCase

 def setUp(self):

   # Restore our log
   stream_handler.stream = sys.stdout

   self.evpn_proxy = EVPNProxy(router_id="1.1.1.4")

   # Assumes a BGP neighbor config in SRL
   # Cannot 'await'
   self.evpn_proxy.connectBGP_EVPN() # TODO wait for connect event

   eventlet.sleep(10)

   self.assertTrue( self.evpn_proxy.isEVPNVTEP(VTEP3),
     f"Proxy failed to detect EVPN VTEP {VTEP3}" )

   # Requires VTEP3/VTEP4 to be peered AND VTEP3 as Route Reflector
   self.assertTrue( self.evpn_proxy.isEVPNVTEP(VTEP4),
     f"Proxy failed to detect EVPN VTEP {VTEP4}" )

   self.evpn_proxy.addStaticVTEP( VNI, EVI, VTEP1 )
   self.evpn_proxy.addStaticVTEP( VNI, EVI, VTEP2 )

 def tearDown(self):
   print( "TEARDOWN - shutdown EVPN proxy" )
   self.evpn_proxy.shutdown()
   eventlet.sleep(1)

 def test_1_normal_scenario_arp_request_broadcast(self,src=VTEP1,dst=VTEP3):
   # ARP request broadcast to all proxies
   self.evpn_proxy.rxVXLAN_ARP( VNI, src, dst, MAC1 )
   eventlet.sleep(1)

   self.assertEqual( self.evpn_proxy.checkAdvertisedRoute(VNI,MAC1), src,
    "proxy failed to advertise correct VTEP" )

 # Case: ARP response sent from static VTEP (or lost ARP broadcast request)

 # Case: MAC move static VTEP1 to static VTEP2
 def test_2_normal_scenario_mac_move(self):
  self.test_1_normal_scenario_arp_request_broadcast(src=VTEP1,dst=VTEP3)

  # Emulate MAC1 moving to static VTEP2
  self.test_1_normal_scenario_arp_request_broadcast(src=VTEP2,dst=VTEP3)

 # Case: MAC move static VTEP1 to EVPN VTEP4
 def test_3_normal_scenario_mac_move_to_evpn(self):
  self.test_1_normal_scenario_arp_request_broadcast(src=VTEP1,dst=VTEP3)

  # Emulate MAC1 moving to EVPN VTEP4, detected via ARP
  self.evpn_proxy.rxVXLAN_ARP( VNI, VTEP4, VTEP3, MAC1 )
  eventlet.sleep(1)

  self.assertIsNone( self.evpn_proxy.checkAdvertisedRoute(VNI,MAC1),
    "proxy failed to withdraw route for MAC moved to EVPN VTEP" )

 # Case: MAC move static VTEP1 to EVPN VTEP4, detected through RT2 update
 def test_4_normal_scenario_mac_move_to_evpn_detected_via_evpn(self):
  self.test_1_normal_scenario_arp_request_broadcast(src=VTEP1,dst=VTEP3)

  # Emulate MAC1 moving to EVPN VTEP4, seen via RT2
  self.evpn_proxy.rxEVPN_RT2( VNI, MAC1, VTEP4, is_from_proxy=False )
  eventlet.sleep(1)

  self.assertIsNone( self.evpn_proxy.checkAdvertisedRoute(VNI,MAC1),
    "proxy failed to withdraw route for MAC moved to EVPN VTEP through RT2" )


if __name__ == '__main__':
  # asyncio.run( unittest.main() ) # Python 3.7+
  # loop = asyncio.get_event_loop()
  # loop.run_until_complete( unittest.main() )
  unittest.main()
