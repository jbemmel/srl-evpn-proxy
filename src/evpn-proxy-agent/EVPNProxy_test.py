import unittest

import EVPNProxy
import eventlet

#
# Run: python3 -m unittest discover . "*_test.py"
#
class EVPNProxyTestCase(unittest.TestCase):

 VNI = 1234

 MAC1 = "00:11:22:33:44:01"
 MAC2 = "00:11:22:33:44:02"

 # Static VTEPs (TODO emulate dynamic EVPN VTEPs too, by calling rxEVPN_RT2)
 VTEP1 = "1.1.1.1"
 VTEP2 = "2.2.2.2"

 def setUp(self):
  self.evpn_proxy1 = EVPNProxy(loopback="127.0.0.1").connectBGP_EVPN(
    peer="127.0.0.2", local_bgp_port=179, remote_bgp_port=1179,
    connect_mode='passive' )

  self.evpn_proxy2 = EVPNProxy(loopback="127.0.0.2").connectBGP_EVPN(
    peer="127.0.0.1", local_bgp_port=1179, remote_bgp_port=179,
    connect_mode='active' )

 def tearDown(self):
  self.evpn_proxy1.shutdown()
  self.evpn_proxy2.shutdown()

 def test_1_normal_scenario_arp_request_broadcast(self,vtep=VTEP1):
  # ARP request broadcast to both proxies
  self.evpn_proxy1.rxVXLAN_ARP( VNI, MAC1, vtep )
  self.evpn_proxy2.rxVXLAN_ARP( VNI, MAC1, vtep )

  eventlet.sleep(1)

  self.assertEqual( self.evpn_proxy1.checkAdvertisedRoute(VNI,MAC1), vtep,
    "proxy1 failed to advertise correct VTEP" )
  self.assertEqual( self.evpn_proxy2.checkAdvertisedRoute(VNI,MAC1), vtep,
    "proxy2 failed to advertise correct VTEP" )

 # Case: ARP response sent from static VTEP (or lost ARP broadcast request)
 def test_2_normal_scenario_arp_response_unicast(self,vtep=VTEP1):
  # ARP response unicast to one proxy
  self.evpn_proxy1.rxVXLAN_ARP( VNI, MAC1, vtep )

  eventlet.sleep(1)

  self.assertEqual( self.evpn_proxy1.checkAdvertisedRoute(VNI,MAC1), vtep,
     "proxy1 failed to advertise VTEP learned from ARP reply" )
  self.assertEqual( self.evpn_proxy2.checkAdvertisedRoute(VNI,MAC1), vtep,
     "proxy2 failed to advertise VTEP learned via EVPN RT2" )

 # Case: MAC move static VTEP1 to static VTEP2
 def test_3_normal_scenario_mac_move(self):
  self.test_1_normal_scenario_arp_request_broadcast(VTEP1)

  # Emulate MAC1 moving to static VTEP2
  self.test_1_normal_scenario_arp_request_broadcast(VTEP2)

if __name__ == '__main__':
    unittest.main()
