#!/usr/bin/env python3
from scapy.all import *

print("statrting to sniff packets...")

def print_pkt(pkt):
    pkt.show()

pkt = sniff(filter= 'dst net 172.12.3.0/24', prn=print_pkt)
