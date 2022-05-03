#!/bin/bash

set -e

gcc -o pcap 0816034.c -lpcap
docker cp pcap BRGr:/root
docker exec -it BRGr /root/pcap
