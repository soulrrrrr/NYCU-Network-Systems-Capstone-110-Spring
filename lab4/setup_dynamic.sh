#!/bin/bash

# author: soulr, 1am9trash

set -e # the shell exits when a command fails

change_color_echo() {
    echo -e -n "\033[0;31m"
    echo "${1}"
    echo -e -n "\033[0m"
}

delete_docker() {
    if [ -z "$(docker ps -a -q)" ]; then
        change_color_echo "No need to delete docker"
    else
        change_color_echo "Deleting docker"
        docker rm -f $(docker ps -a -q)
    fi
}

build_docker() {
    change_color_echo "Building docker ${1}"
    docker run --privileged --cap-add NET_ADMIN \
    --cap-add NET_BROADCAST -d -it \
    --name ${1} ubuntu:16.04
}

install() {
    change_color_echo "Installing ${2} for ${1}"
    docker exec ${1} apt-get install ${2} -y
}

build_link() {
    change_color_echo "Creating link for ${1} ${2}"
    ip link add ${1}${2}veth type veth peer name ${2}${1}veth

    change_color_echo "Setting link for ${1} ${2}"
    ip link set ${1}${2}veth netns $(docker inspect -f {{.State.Pid}} ${1})
    ip link set ${2}${1}veth netns $(docker inspect -f {{.State.Pid}} ${2})

    change_color_echo "Setting ip for ${1} ${2}"
    docker exec ${1} ip addr add ${3}/24 dev ${1}${2}veth
    if [ ${#} -eq 4 ]; then
        docker exec ${2} ip addr add ${4}/24 dev ${2}${1}veth
    fi

    change_color_echo "Running link"
    docker exec ${1} ip link set ${1}${2}veth up
    docker exec ${2} ip link set ${2}${1}veth up
}

set_route() {
    change_color_echo "Setting route"
    docker exec ${1} ip route del default
    docker exec ${1} ip route add default via ${2}
    docker exec ${1} ip route show
}

set_gretap() {
    change_color_echo "Setting gretap on ${1}"
    docker exec ${1} ip link add GRETAP type gretap remote ${2} local ${3}
    docker exec ${1} ip link set GRETAP up
    docker exec ${1} ip link show GRETAP
    docker exec ${1} ip link add br0 type bridge
    docker exec ${1} ip link set ${4} master br0
    docker exec ${1} ip link set GRETAP master br0
    docker exec ${1} ip link set br0 up
}

set_gretap_2() {
    change_color_echo "Setting gretap_2 on ${1}"
    docker exec ${1} ip link add GRETAP_1 type gretap remote ${2} local ${4}
    docker exec ${1} ip link set GRETAP_1 up
    docker exec ${1} ip link add GRETAP_2 type gretap remote ${3} local ${4}
    docker exec ${1} ip link set GRETAP_2 up
    docker exec ${1} ip link add br0 type bridge
    docker exec ${1} ip link set ${5} master br0
    docker exec ${1} ip link set GRETAP_1 master br0
    docker exec ${1} ip link set GRETAP_2 master br0
    docker exec ${1} ip link set br0 up
}

set_bridge() {
    docker exec ${1} ip link add br0 type bridge
    docker exec ${1} ip link set ${2} master br0
    docker exec ${1} ip link set br0 up
}

set_quagga() {
    change_color_echo "Setting quagga ${1}"
    docker cp sysctl.conf ${1}:/etc/sysctl.conf
    docker exec ${1} sysctl -p
    docker cp daemons ${1}:/etc/quagga/daemons
    docker cp zebra${1}.conf ${1}:/etc/quagga/zebra.conf
    docker cp bgpd${1}.conf ${1}:/etc/quagga/bgpd.conf
    docker exec ${1} /etc/init.d/quagga restart
}

delete_docker

build_docker h1
build_docker h2
build_docker GWr
build_docker BRG1
build_docker BRG2
build_docker BRGr
build_docker R1
build_docker R2

install BRGr libpcap-dev
install BRG1 'dialog apt-utils'
install BRG2 'dialog apt-utils'
install BRGr 'dialog apt-utils'
install BRG1 bridge-utils
install BRG2 bridge-utils
install BRGr bridge-utils

build_link h1 BRG1 10.0.1.1
build_link h2 BRG2 10.0.1.2
build_link GWr BRGr 10.0.1.254
build_link BRG1 R1 140.114.0.1 140.114.0.2
build_link BRG2 R1 140.115.0.1 140.115.0.2
build_link BRGr R2 140.113.0.1 140.113.0.2
build_link R1 R2 140.116.0.1 140.116.0.2

#set_route h1 10.0.1.3
#set_route h2 10.0.1.4
#set_route GWr 10.0.1.253
set_route BRG1 140.114.0.2
set_route BRG2 140.115.0.2
set_route BRGr 140.113.0.2


set_gretap BRG1 140.113.0.1 140.114.0.1 BRG1h1veth
set_gretap BRG2 140.113.0.1 140.115.0.1 BRG2h2veth
set_bridge BRGr BRGrGWrveth
#set_gretap_2 BRGr 140.114.0.1 140.115.0.1 140.113.0.1 BRGrGWrveth

set_quagga R1
set_quagga R2


change_color_echo "setup_dynamic.sh finished."
change_color_echo "Press enter to finish."
read

