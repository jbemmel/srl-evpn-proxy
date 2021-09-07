import eventlet
import unittest
# import aiounittest # until Python 3.8 is available
import logging
import sys
import asyncio

from dask.distributed import Client, Queue

from ryu.lib import hub

# unittest replaces sys.stdout/sys.stderr
logger = logging.getLogger()
logger.level = logging.INFO # DEBUG
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)

# from EVPNProxy import EVPNProxy

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


 def tearDown(self):
   print( "TEARDOWN - shutdown EVPN proxy" )

 def test_1_passes(self):
   print( "test_1_normal_scenario_arp_request_broadcast" )

 def test_2_fails(self):
   print( "test_2_fails" )
   self.assertTrue( False, "Testing failed test 2" )

 def test_3_passes_on_worker_2(self):
   print( "test_3_passes_on_worker_2" )
   self.assertTrue( False, "This must be worker1?" )


if __name__ == '__main__':
  # asyncio.run( unittest.main() ) # Python 3.7+
  # loop = asyncio.get_event_loop()
  # loop.run_until_complete( unittest.main() )
  schedulerAddr = (sys.argv[1]+":8786") if len(sys.argv)>1 else None
  print( f"Starting Client, scheduler={schedulerAddr}" )
  if schedulerAddr is None:
     client = Client( processes=False, n_workers=1, threads_per_worker=1, host="tcp://10.0.2.15:8786" )  # set up local Dash cluster
  else:
     client = Client( address=schedulerAddr )  # Connect to remote
  # if schedulerAddr is not None:
      # client.cluster.scheduler.broadcast( "start" )

  queue = Queue( name="EVPNProxy_Test", client=client )
  if schedulerAddr is None:
      print( client.cluster )
      msg = queue.get()
      print( msg )
  else:
      queue.put( "Message from Proxy2 worker" )
      print( "Message sent!" )

  # unittest.main()
