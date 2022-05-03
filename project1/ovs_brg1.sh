#!/bin/bash

# https://www.cnblogs.com/goldsunshine/p/13056429.html

#docker exec -it BRG1 ovs-vsctl set bridge mybridge datapath_type=netdev
#docker exec -it BRG1 ovs-vsctl set bridge mybridge protocols=OpenFlow13
docker exec -it BRG1 ovs-ofctl del-meter mybridge meter=1 -O OpenFlow13
docker exec -it BRG1 ovs-ofctl add-meter mybridge meter=1,kbps,band=type=drop,rate=1000 -O OpenFlow13
docker exec -it BRG1 ovs-ofctl dump-meters mybridge -O OpenFlow13
docker exec -it BRG1 ovs-ofctl add-flow mybridge in_port=BRG1h1veth,action=meter:1,output:GRETAP -O OpenFlow13
docker exec -it BRG1 ovs-ofctl add-flow mybridge in_port=GRETAP,action=output:BRG1h1veth -O OpenFlow13

#ethtool -K ens33 tx off
#docker exec -it h1 ethtool -K h1BRG1veth tx off
