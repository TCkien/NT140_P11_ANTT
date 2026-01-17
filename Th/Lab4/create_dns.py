from scapy.all import *

# Thông tin cần điền
target_dns_server = "192.168.108.139"  # Địa chỉ IP của DNS server mục tiêu
source_ip = "192.168.108.130"  # IP của máy tấn công
query_domain = "www.example.net"  # Tên miền mục tiêu
source_port = 12345  # Port nguồn ngẫu nhiên

# Tạo DNS request
Qdsec = DNSQR(qname=query_domain)
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=Qdsec)
ip = IP(dst=target_dns_server, src=source_ip)
udp = UDP(dport=53, sport=source_port, chksum=0)
request = ip/udp/dns

# Gửi request
send(request)
