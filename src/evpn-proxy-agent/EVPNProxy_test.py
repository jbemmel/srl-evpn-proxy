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

MAC1 = "00:11:22:33:44:01"
MAC2 = "00:11:22:33:44:02"

# Static VTEPs (TODO emulate dynamic EVPN VTEPs too, by calling rxEVPN_RT2)
VTEP1 = "1.1.1.1"
VTEP2 = "2.2.2.2"

# BGP ports, don't interfere with SRL
BGP_PORT1=10179
BGP_PORT2=20179

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

 def tearDown(self):
   print( "TEARDOWN" )
   self.evpn_proxy.shutdown()

 def test_1_normal_scenario_arp_request_broadcast(self,vtep=VTEP1):
   # ARP request broadcast to both proxies
   self.evpn_proxy.rxVXLAN_ARP( VNI, MAC1, vtep )
   eventlet.sleep(1)

   self.assertEqual( self.evpn_proxy.checkAdvertisedRoute(VNI,MAC1), vtep,
    "proxy failed to advertise correct VTEP" )

 # Case: ARP response sent from static VTEP (or lost ARP broadcast request)

 # Case: MAC move static VTEP1 to static VTEP2
 def test_3_normal_scenario_mac_move(self):
  self.test_1_normal_scenario_arp_request_broadcast(VTEP1)

  # Emulate MAC1 moving to static VTEP2
  self.test_1_normal_scenario_arp_request_broadcast(VTEP2)

if __name__ == '__main__':
  unittest.main()
