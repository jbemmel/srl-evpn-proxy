# Simple Python function to send ARP request and determine MAC from response

import subprocess

def arping(ip,interface,count=2):
  process = subprocess.run(['/usr/bin/sudo','/usr/sbin/ip','netns','exec','srbase-default',
                            '/usr/sbin/arping','-I',interface,'-c',str(count),ip],
                            stdout=subprocess.PIPE,
                            universal_newlines=True)
  for line in process.stdout.split('\n'):
    if line[:13] == "Unicast reply":
      mac = line.split(' ')[4][1:-1] # Remove '['']'
      # print( mac )
      return mac

  return None

mac = arping('192.168.127.129','e1-49.0')
print( mac )
