mkdir -p /var/run/netns
./veth_setup.sh

intf0="veth14"
intf1="veth16"
servername="test"
server_mac="00:00:00:00:00:23"
server_ip="7.23.7.23"
server_mac="00:00:00:00:00:23"
docker run -ti -u root -d --rm --name=$servername --net=none --privileged flask
docker cp web $servername:.
docker exec -d $servername mv web/* .
PID=$(docker inspect -f '{{.State.Pid}}' $servername)
ln -s /proc/$PID/ns/net /var/run/netns/$PID
ip link set $intf0 netns $PID
ip link set $intf1 netns $PID
ip netns exec $PID ip link set dev $intf0 name eth0 
ip netns exec $PID ip link set dev $intf1 name eth1 
ip netns exec $PID ifconfig eth0 hw ether $server_mac
ip netns exec $PID ifconfig eth1 hw ether $server_mac
ip netns exec $PID ip link set eth0 up 
ip netns exec $PID ip link set eth1 up 
ip netns exec $PID ip addr del 127.0.0.1/8 dev lo
ip netns exec $PID ip addr add $server_ip/24 dev lo
xterm -T $servername -hold -e docker exec -it $servername python3 web.py 1 &
