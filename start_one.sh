mkdir -p /var/run/netns
./veth_setup.sh

intfcli0="veth10"
intfser0="veth11"
intfcli1="veth12"
intfser1="veth13"
clientname="h0"
servername="h1"
cip="10.0.0.1"
vip="7.23.7.23"
climac="00:00:00:00:00:10"
sermac="00:00:00:00:00:02"

docker run -t -i -u root -d --rm -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --name=$clientname --net=none --privileged firefox
docker run -t -i -u root -d --rm --name=$servername --net=none --privileged flask

PID1=$(docker inspect -f '{{.State.Pid}}' $clientname)
PID2=$(docker inspect -f '{{.State.Pid}}' $servername)

ln -s /proc/$PID1/ns/net /var/run/netns/$PID1
ip link set $intfcli0 netns $PID1
ip link set $intfcli1 netns $PID1
ip netns exec $PID1 ip link set dev $intfcli0 name eth0 
ip netns exec $PID1 ip link set dev $intfcli1 name eth1
ip netns exec $PID1 ifconfig eth0 hw ether $climac
ip netns exec $PID1 ifconfig eth1 hw ether $climac
ip netns exec $PID1 ip link set eth0 up 
ip netns exec $PID1 ip link set eth1 up 
ip netns exec $PID1 ip addr del 127.0.0.1/8 dev lo
ip netns exec $PID1 ip addr add $cip/24 dev lo
ip netns exec $PID1 route add -host $vip dev eth0
ip netns exec $PID1 arp -s $vip $sermac

docker cp web $servername:.
docker exec -d $servername mv web/* .
ln -s /proc/$PID2/ns/net /var/run/netns/$PID2
ip link set $intfser0 netns $PID2
ip link set $intfser1 netns $PID2
ip netns exec $PID2 ip link set dev $intfser0 name eth0 
ip netns exec $PID2 ip link set dev $intfser1 name eth1 
ip netns exec $PID2 ifconfig eth0 hw ether $sermac
ip netns exec $PID2 ifconfig eth1 hw ether $sermac
ip netns exec $PID2 ip link set eth0 up 
ip netns exec $PID2 ip link set eth1 up 
ip netns exec $PID2 ip addr del 127.0.0.1/8 dev lo
ip netns exec $PID2 ip addr add $vip/24 dev lo
ip netns exec $PID2 route add -host $cip dev eth1
ip netns exec $PID2 arp -s $cip $climac
xterm -T $servername -hold -e docker exec -it $servername python3 web.py 1 &

echo $PID1
echo $PID2
