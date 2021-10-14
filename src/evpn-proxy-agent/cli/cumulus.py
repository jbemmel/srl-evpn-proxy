import subprocess, json, logging

def retrieve_dynamic_MACs(vtep_ip,cumulus_user="root",cumulus_password="root"):
   """
   Uses the Cumulus REST API to retrieve a list of MAC addresses learnt on its
   physical interfaces
   """

   try:
      res = send_RPC_command("show bridge macs dynamic json",vtep_ip,cumulus_user,cumulus_password)
      if res.stdout:
         macs = json.loads( res.stdout )
         # Take only MACs on Ethernet interfaces, TODO could filter on VLAN
         return [ m['mac'] for m in macs if m['ifname'][0]=='e' ]
   except Exception as err:
      logging.error( f"Cumulus API query for MACs returned an error; REST API enabled on VTEP {vtep_ip}? {err}" )
      raise err
   return []

 def send_RPC_command(cmd,vtep_ip,cumulus_user="root",cumulus_password="root"):
   # Assumes the VTEP IP is reachable through the default netns, ACLs allow it
   _c = ( "/usr/sbin/ip netns exec srbase-default " +
         f"/usr/bin/curl -X POST -k -s -u {cumulus_user}:{cumulus_password} " +
         f"-H \"Content-Type: application/json\" -d '{{\"cmd\": \"{cmd}\"}}' " +
         f"https://{vtep_ip}:8080/nclu/v1/rpc" )

   return subprocess.run( _c, shell=True, stdout=subprocess.PIPE, check=True, timeout=3 )
