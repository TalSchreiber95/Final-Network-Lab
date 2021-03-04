from scapy.all import *

a=IP()
a.dst= '10.0.1.3'
b= ICMP()
p= a/b
send(p)
