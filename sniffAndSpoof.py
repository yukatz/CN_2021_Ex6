#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
       if pkt[ICMP].type == 8:
           print("Original Packet...")
           print("Src IP:", pkt[IP].src)
           print("Dst IP:",pkt[IP].dst)
       
           ip = IP(src = pkt[IP].dst, dst = pkt[IP].src, ihl = pkt[IP].ihl)
           icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
           data = pkt[Raw].load
           newpkt = ip/icmp/data
       

           
           print("Spoofed Packet...")
           print("Src IP:", newpkt[IP].src)
           print("Dst IP:",newpkt[IP].dst)
       
           send(newpkt, verbose=0)
      
pkt = sniff(filter='icmp', prn=spoof_pkt)

