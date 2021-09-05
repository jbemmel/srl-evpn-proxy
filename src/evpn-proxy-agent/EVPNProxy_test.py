import eventlet

eventlet.monkey_patch() # BGPSpeaker needs this

import unittest
import logging
import sys

# unittest replaces sys.stdout/sys.stderr
logger = logging.getLogger()
logger.level = logging.DEBUG
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

#
# Run: ip netns exec srbase-default python3 -m unittest EVPNProxy_test.EVPNProxyTestCase -v
#
# Note that Ryu only supports a single BGPSpeaker per Python process, hence we
# need to create multiple test processes (one per EVPN proxy)
#
# These tests are designed to be run inside the srbase_default namespace on SRL
#
class EVPNProxyTestCase(unittest.TestCase):

 def setUp(self):

   # Restore our log
   stream_handler.stream = sys.stdout

   self.evpn_proxy = EVPNProxy(router_id="1.1.1.4")

   # Assumes a BGP neighbor config in SRL
   self.evpn_proxy.connectBGP_EVPN()
   eventlet.sleep(5)
   self.assertTrue( self.evpn_proxy.isEVPNPeer(VTEP3),
     "Proxy failed to detect EVPN VTEP" )

   self.evpn_proxy.addStaticVTEP( VNI, EVI, VTEP1 )
   self.evpn_proxy.addStaticVTEP( VNI, EVI, VTEP2 )

 def tearDown(self):
   print( "TEARDOWN" )
   self.evpn_proxy.shutdown()

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

if __name__ == '__main__':
  unittest.main()
