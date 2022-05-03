#!/bin/bash

# author: 1am9trash
# modifier: soulr

set -e # the shell exits when a command fails

change_color_echo() {
    echo -e -n "\033[0;31m"
    echo "${1}"
    echo -e -n "\033[0m"
}

apparmor() {
    change_color_echo "remember modify apparmor settings (Lab2 homework.pdf P9) & set net4.ip_forward=1"
}

delete_docker() {
    if [ -z "$(docker ps -a -q)" ]; then
        change_color_echo "No need to delete docker"
    else
        change_color_echo "Deleting docker"
        docker rm -f $(docker ps -a -q)
    fi
}

clean() {
    change_color_echo "Cleanup"
    delete_docker
    if [ -z "$(ip link show br0 2>/dev/null)" ]; then
        change_color_echo "br0 not found"
    else
        ip link set br0 down
        ip link delete br0 type bridge
    fi
    kill -9 $(cat /run/dhcp-server-dhcpd.pid) || true
    iptables -t nat -D POSTROUTING 1 || true
}

build_docker() {
    change_color_echo "Building docker ${1}"
    docker run --privileged --cap-add NET_ADMIN \
    --cap-add NET_BROADCAST -d -it \
    --name ${1} project1-soulr
    docker cp sysctl.conf ${1}:/etc/sysctl.conf
    docker exec ${1} sysctl -p
}

build_bridge() {
    ip link add ${1} type bridge
    ip link set ${1} up
}

install() {
    change_color_echo "Installing ${2} for ${1}"
    docker exec ${1} apt-get install ${2} -y
}

create_link() {
    change_color_echo "Creating link for ${1} and ${2}"
    ip link add ${1}${2}veth type veth peer name ${2}${1}veth
}

set_master_br0() {
    change_color_echo "Set master of br0${1}veth to br0 in VM"
    ip link set br0${1}veth master br0
}

set_ns() {
    change_color_echo "Setting network namespace for ${1}${2}veth"
    ip link set ${1}${2}veth netns $(docker inspect -f {{.State.Pid}} ${1})
}

set_ip() {
    change_color_echo "Setting ip for ${1}${2}veth in docker ${1}"
    docker exec ${1} ip addr add ${3}/24 dev ${1}${2}veth
}

vm_set_ip() {
    change_color_echo "Setting ip for ${1}${2}veth in VM"
    ip addr add ${3}/24 dev ${1}${2}veth
}

up() {
    change_color_echo "Running interface ${1}${2}veth in docker ${1}"
    docker exec ${1} ip link set ${1}${2}veth up
}

vm_up() {
    change_color_echo "Running interface ${1}${2}veth in VM"
    ip link set ${1}${2}veth up
}

set_dhcp_edge() {
    change_color_echo "Set dhcp edge"
    docker cp ./dhcpd_edge.conf edge:/
    docker exec -it edge touch /var/lib/dhcp/dhcpd.leases
    docker exec -it edge /usr/sbin/dhcpd 4 -pf /run/dhcp-server-dhcpd.pid -cf /dhcpd_edge.conf edgebr0veth
}

vm_set_dhcp_GWr() {
    change_color_echo "Set dhcp GWr in VM"
    if [[ ! -f /var/lib/dhcp/dhcpd.leases ]]; then
        touch /var/lib/dhcp/dhcpd.leases
        chmod 777 /var/lib/dhcp/dhcpd.leases
    fi
    /usr/sbin/dhcpd 4 -pf /run/dhcp-server-dhcpd.pid -cf ./dhcpd_outer.conf GWrBRGrveth
}

set_route_ip() {
    change_color_echo "Setting route ip"
    docker exec ${1} ip route add ${2} via ${3}
}

set_route_dev() {
    change_color_echo "Setting route dev"
    docker exec ${1} ip route add ${2} dev ${3}
}

set_route_def() {
    change_color_echo "Setting route def"
    docker exec ${1} ip route del default
    docker exec ${1} ip route add default via ${2}
}

set_gretap() {
    change_color_echo "Setting gretap on ${1} (to ${2})"
    docker exec ${1} ip fou add port ${5} ipproto 47
    docker exec ${1} ip link add GRETAP type gretap remote ${3} local ${4} key ${5} encap fou encap-sport ${5} encap-dport ${6}
    docker exec ${1} ip link set GRETAP up
    docker exec ${1} ip link add br0 type bridge
    docker exec ${1} ip link set ${7} master br0
    docker exec ${1} ip link set GRETAP master br0
    docker exec ${1} ip link set br0 up
}

set_gretap_ovs() {
    change_color_echo "Setting gretap on ${1} (to ${2})"
    docker exec ${1} /usr/share/openvswitch/scripts/ovs-ctl start || true
    docker exec ${1} ip fou add port ${5} ipproto 47
    docker exec ${1} ip link add GRETAP type gretap remote ${3} local ${4} key ${5} encap fou encap-sport ${5} encap-dport ${6}
    docker exec ${1} ip link set GRETAP up
    docker exec ${1} ovs-vsctl add-br mybridge
    docker exec ${1} ovs-vsctl add-port mybridge BRG1h1veth
    docker exec ${1} ovs-vsctl add-port mybridge GRETAP
    docker exec ${1} ifconfig mybridge up
}

apparmor
read
clean
iptables -P FORWARD ACCEPT # ipv4 forward
modprobe fou # enable fou
build_docker h1
build_docker h2
build_docker BRG1
build_docker BRG2
build_docker BRGr
build_docker edge
build_docker r1 # no-name router between edge & BRGr

# install 
install h1 ethtool
# nodes

# h1-BRG1
create_link h1 BRG1
set_ns h1 BRG1
set_ns BRG1 h1
up h1 BRG1
up BRG1 h1

# h2-BRG2
create_link h2 BRG2
set_ns h2 BRG2
set_ns BRG2 h2
up h2 BRG2
up BRG2 h2

# br0 in VM
build_bridge br0

# br0-BRG1
create_link br0 BRG1
set_master_br0 BRG1
set_ns BRG1 br0
vm_up br0 BRG1
up BRG1 br0

# br0-BRG2
create_link br0 BRG2
set_master_br0 BRG2
set_ns BRG2 br0
vm_up br0 BRG2
up BRG2 br0

# br0-edge
create_link br0 edge
set_master_br0 edge
set_ns edge br0
vm_up br0 edge
up edge br0

# edge-r1
create_link edge r1
set_ns edge r1
set_ns r1 edge
set_ip edge r1 140.114.0.1
set_ip r1 edge 140.114.0.2
up edge r1
up r1 edge

# BRGr-r1
create_link BRGr r1
set_ns BRGr r1
set_ns r1 BRGr
set_ip BRGr r1 140.113.0.2
set_ip r1 BRGr 140.113.0.1
up BRGr r1
up r1 BRGr

# BRGr-GWr
create_link BRGr GWr
set_ns BRGr GWr
up BRGr GWr
vm_up GWr BRGr


# set dhcp
set_ip edge br0 172.27.0.1 # DHCP server
set_dhcp_edge
vm_set_ip GWr BRGr 20.0.1.1
vm_set_dhcp_GWr
docker exec -it BRG1 dhclient BRG1br0veth
docker exec -it BRG2 dhclient BRG2br0veth


# set route
set_route_ip BRG1 20.0.1.1/32 172.27.0.1
set_route_dev BRG1 20.0.1.0/24 BRG1h1veth
set_route_ip BRG2 20.0.1.1/32 172.27.0.1
set_route_dev BRG2 20.0.1.0/24 BRG2h2veth
set_route_ip  edge 140.113.0.0/24 140.114.0.2
set_route_ip  BRGr 140.114.0.0/24 140.113.0.1
set_route_def BRG1 172.27.0.1
set_route_def BRG2 172.27.0.1


# set gretap foo
set_gretap_ovs BRG1 BRGr 140.113.0.2 172.27.0.2 11111 33333 BRG1h1veth
set_gretap BRG2 BRGr 140.113.0.2 172.27.0.3 22222 44444 BRG2h2veth

# set gretap on BRGr (test)
#docker exec BRGr ip fou add port 33333 ipproto 47
#docker exec BRGr ip fou add port 44444 ipproto 47
#docker exec BRGr ip link add GRETAP_1 type gretap remote 140.114.0.1 local 140.113.0.2 key 11111 encap fou encap-sport 33333 encap-dport 11111
#docker exec BRGr ip link add GRETAP_2 type gretap remote 140.114.0.1 local 140.113.0.2 key 22222 encap fou encap-sport 44444 encap-dport 22222
#docker exec BRGr ip link set GRETAP_1 up
#docker exec BRGr ip link set GRETAP_2 up
docker exec BRGr ip link add br0 type bridge
docker exec BRGr ip link set BRGrGWrveth master br0
#docker exec BRGr ip link set GRETAP_1 master br0
#docker exec BRGr ip link set GRETAP_2 master br0
#docker exec BRGr ip link set br0 up


# set nat
docker exec -it edge iptables -t nat -A POSTROUTING -s 172.27.0.0/24 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 20.0.1.0/24 -j MASQUERADE

#docker exec -it h1 dhclient h1BRG1veth
#docker exec -it h2 dhclient h2BRG2veth

change_color_echo "setup.sh finished."
change_color_echo "Press enter to finish."
read
