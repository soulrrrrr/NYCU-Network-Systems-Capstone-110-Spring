#! /usr/bin/python
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, Switch
from mininet.cli import CLI

def topology():
    net = Mininet()

    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    s1 = net.addSwitch('s1', failMode='standalone')
    net.addLink('h1', 's1')
    net.addLink('h2', 's1')

    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()
