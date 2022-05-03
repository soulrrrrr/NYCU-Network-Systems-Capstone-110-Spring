#!/bin/bash

docker exec -it h1 dhclient h1BRG1veth
docker exec -it h1 ip route del default
docker exec -it h1 ip route add default via 20.0.1.1

docker exec -it h2 dhclient h2BRG2veth
docker exec -it h2 ip route del default
docker exec -it h2 ip route add default via 20.0.1.1
