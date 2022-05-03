#!/bin/bash

set -e

change_color_echo() {
    echo -e -n "\033[0;31m"
    echo "${1}"
    echo -e -n "\033[0m"
}

ip_r() {
    change_color_echo "${1} ip r"
    docker exec ${1} ip r
}

ip_r h1
ip_r h2

ip_r BRG1
ip_r BRG2
ip_r BRGr

ip_r edge
ip_r r1
