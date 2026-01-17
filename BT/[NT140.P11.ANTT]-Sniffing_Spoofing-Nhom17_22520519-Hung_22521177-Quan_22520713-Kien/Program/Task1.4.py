#!/usr/bin/env python3
from scapy.all import *
import sys

nonexistent_internet_host = "1.2.3.4"
nonexistent_lan_host = "10.9.0.99"
existent_internet_host = "8.8.8.8"

def spoof_icmp_reply(request_packet):
    if request_packet[ICMP].type == 8:  # Check if it's an ICMP Echo Request
        ip_src = request_packet[IP].src
        ip_dst = request_packet[IP].dst
        print(f"Received ping request from {ip_src} to {ip_dst}")
        
        reply_packet = IP(src=ip_dst, dst=ip_src) / ICMP(type=0, id=request_packet[ICMP].id, seq=request_packet[ICMP].seq)
        send(reply_packet, verbose=0)
        print(f"Sent spoofed reply to {ip_src} pretending to be {ip_dst}")
        
def sniff_and_spoof():
    filter_exp = f"icmp and (dst {nonexistent_internet_host} or dst {nonexistent_lan_host} or dst {existent_internet_host})"
    print(f"Sniffing for ICMP requests to {nonexistent_internet_host}, {nonexistent_lan_host}, and {existent_internet_host}")
    sniff(filter=filter_exp, prn=spoof_icmp_reply)

sniff_and_spoof()
