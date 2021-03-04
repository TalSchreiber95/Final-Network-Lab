from scapy.all import *


def spoof(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8: # type 8 = echo
        print("Forging...")
        #the spoofing.
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) #type 0 = reply
        data = pkt[Raw].load
        newpkt = ip/icmp/data
        send(newpkt, verbose=0)
        print("Spoofed.")

pkt = sniff(filter='icmp and src host 10.0.2.15', prn=spoof)
