import unittest
import logging

from EVPNProxy import EVPNProxy
import eventlet
from ryu.lib import hub

eventlet.monkey_patch() # BGPSpeaker needs this

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
# Run: python3 -m unittest discover . "*_test.py"
#
class EVPNProxyTestCase(unittest.TestCase):

 def setUp(self):

   def _startProxy(loopback,local_port,peer,remote_port,connect_mode):
      evpn_proxy = EVPNProxy(loopback=loopback)

      def thread():
       evpn_proxy.connectBGP_EVPN(
      peer=peer, local_bgp_port=local_port, remote_bgp_port=remote_port,
      connect_mode=connect_mode )
      t = hub.spawn( thread )
      eventlet.sleep(3)
      return evpn_proxy, t

   self.evpn_proxy1, self.t1 = _startProxy("127.0.0.1",BGP_PORT1,"127.0.0.2",BGP_PORT2,'passive')
   self.evpn_proxy2, self.t2 = _startProxy("127.0.0.2",BGP_PORT2,"127.0.0.1",BGP_PORT1,'active')

 def tearDown(self):
   self.evpn_proxy1.shutdown()
   hub.kill( self.t1 )
   self.evpn_proxy2.shutdown()
   hub.kill( self.t2 )

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
  logging.basicConfig(
    filename='EVPNProxy_test.log',
    format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
    level=logging.DEBUG )

  unittest.main()
