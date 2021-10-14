import subprocess, json, logging

def retrieve_dynamic_MACs(vtep_ip,cumulus_user="root",cumulus_password="root"):
   """
   Uses the Cumulus REST API to retrieve a list of MAC addresses learnt on its
   physical interfaces
   """

   # Assumes the VTEP IP is reachable through the default netns, ACLs allow it
   cmd = (f"/usr/sbin/ip netns exec srbase-default /usr/bin/curl -X POST -k -s -u {cumulus_user}:{cumulus_password}" +
         " -H \"Content-Type: application/json\" -d '{{\"cmd\": \"show bridge macs dynamic json\"}}' " +
         " https://{vtep_ip}:8080/nclu/v1/rpc")

   try:
     res = subprocess.run( cmd, shell=True, stdout=subprocess.PIPE, check=True, timeout=3 )
     logging.debug( res )
     if res.stdout:
         macs = json.loads( res.stdout )
         # Take only MACs on Ethernet interfaces, TODO could filter on VLAN
         return [ m['mac'] for m in macs if m['ifname'][0]=='e' ]

   except Exception as err:
     logging.error( f"Cumulus API query for MACs returned an error; REST API enabled on VTEP {vtep_ip}? {err}" )
     raise err

   return []
