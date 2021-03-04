from scapy.all import *

a=IP()
a.dst= '10.0.0.1'
b= ICMP()
p= a/b
send(p)

