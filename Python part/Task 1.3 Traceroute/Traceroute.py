#!/usr/bin/env python3
from scapy.all import *

def ttl():
    print("Starting Traceroute")
    for i in range(1,30):
        a=IP()
        a.dst= '172.217.171.196' # google's IP
        a.ttl=i
        b= ICMP()
        send(a/b)

if __name__ == "__main__":
    ttl()

