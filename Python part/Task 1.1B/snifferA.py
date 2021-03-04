#!/usr/bin/env python3
from scapy.all import *

print("statrting to sniff packets...")

def print_pkt(pkt):
    pkt.show()

pkt = sniff(filter= 'icmp', prn=print_pkt)
