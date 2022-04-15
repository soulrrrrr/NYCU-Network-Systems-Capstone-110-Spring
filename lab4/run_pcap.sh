#!/bin/bash

set -e

docker cp 0816034.c BRGr:/root
docker exec -it BRGr gcc /root/pcap.c -o /root/pcap -lpcap
docker exec -it BRGr /root/pcap
