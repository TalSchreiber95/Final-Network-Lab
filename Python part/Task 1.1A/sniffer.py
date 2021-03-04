#!/usr/bin/env python3
from scapy.all import *

print("statrting to sniff packets...")

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='br-37b06ec8a49b', filter= 'icmp', prn=print_pkt)
