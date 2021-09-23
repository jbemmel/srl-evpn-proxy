if ! docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c2; then
  echo "Ping h1->h3 failed!"
  exit $?
fi
MAC1=`docker exec -it clab-static-vxlan-spine-lab-h1 ip a show dev eth1 | awk '/ether/{ print $2 }' | head -1`
MAC2=`docker exec -it clab-static-vxlan-spine-lab-h2 ip a show dev eth1 | awk '/ether/{ print $2 }' | head -1`
echo "MACs h1=${MAC1} h2=${MAC2}, swapping..."
docker exec -it clab-static-vxlan-spine-lab-h1 ip link set address $MAC2 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h1 ip addr flush dev eth1
docker exec -it clab-static-vxlan-spine-lab-h1 ip addr add 10.0.0.102/24 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h2 ip link set address $MAC1 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h2 ip addr flush dev eth1
docker exec -it clab-static-vxlan-spine-lab-h2 ip addr add 10.0.0.101/24 dev eth1
docker exec -it clab-static-vxlan-spine-lab-h1 ping 10.0.0.103 -c2
docker exec -it clab-static-vxlan-spine-lab-h2 ping 10.0.0.103 -c2
