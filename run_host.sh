
mkdir -p /var/run/netns
./veth_setup.sh

idx=0

host_ip=$(ifconfig eth0 | grep "inet addr:" | awk "{print \$2}" | cut -c 6-)

intf="veth$(($idx*2+1))"
hostname="h$idx"
client_ip="10.0.0.10"
client_mac="00:00:00:00:00:0$(($idx+1))"
vip="7.23.7.23"
vmac="00:00:00:00:00:ff"

docker run -t -i -u root -d --rm -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix --name=$hostname --net=none --privileged firefox
PID=$(docker inspect -f '{{.State.Pid}}' $hostname)
ln -s /proc/$PID/ns/net /var/run/netns/$PID
ip link set $intf netns $PID
ip netns exec $PID ip link set dev $intf name eth0 
ip netns exec $PID ifconfig eth0 hw ether $client_mac
ip netns exec $PID ip link set eth0 up 
ip netns exec $PID ip addr add $client_ip/24 dev eth0
ip netns exec $PID route add -host $vip dev eth0
ip netns exec $PID arp -s $vip $vmac
docker cp browse.py $hostname:.

idx=$((idx + 1))

SERVER_NUM=4
idx=1

while [ $idx -le $SERVER_NUM ]
do
    intf0="veth$(($idx*2+1))"
    intf1="veth$(($idx*2+13))"
    intf_host1="veth$(($idx*2+12))"
    hostname="h$idx"
    server_ip0="10.0.0.$idx"
    server_mac0="00:00:00:00:00:0$(($idx+1))"
    server_ip1="20.0.0.$idx"
    server_mac1="20:00:00:00:00:0$(($idx+1))"
    docker run -t -i -u root -d --rm --name=$hostname --net=none --privileged flask
    docker cp web $hostname:.
    docker exec -d $hostname mv web/* .
    PID=$(docker inspect -f '{{.State.Pid}}' $hostname)
    ln -s /proc/$PID/ns/net /var/run/netns/$PID
    ip link set $intf0 netns $PID
    ip link set $intf1 netns $PID
    ip netns exec $PID ip link set dev $intf0 name eth0 
    ip netns exec $PID ip link set dev $intf1 name eth1 
    ip netns exec $PID ifconfig eth0 hw ether $server_mac0
    ip netns exec $PID ifconfig eth1 hw ether $server_mac1
    ip netns exec $PID ip link set eth0 up 
    ip netns exec $PID ip link set eth1 up 
    ip netns exec $PID ip addr add $server_ip0/24 dev eth0
    ip netns exec $PID ip addr add $server_ip1/24 dev eth1
    ip netns exec $PID arp -s $client_ip $client_mac
    ip netns exec $PID route add -host $host_ip dev eth1
    host_mac=$(ifconfig $intf_host1 | grep "HWaddr" | awk '{print $5}')
    ip netns exec $PID arp -s $host_ip $host_mac
    route add -host $server_ip1 dev $intf_host1
    arp -s $server_ip1 $server_mac1
    xterm -T $hostname -hold -e docker exec -it $hostname python3 web.py $idx &
    idx=$((idx + 1))
done
