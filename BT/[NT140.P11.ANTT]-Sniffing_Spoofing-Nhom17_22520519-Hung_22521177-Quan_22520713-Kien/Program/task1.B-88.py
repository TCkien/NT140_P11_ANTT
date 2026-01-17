#!/usr/bin/env python3
from scapy.all import *

# Initialize packet counter
packet_count = 0

def print_pkt(pkt):
  global packet_count
  packet_count += 1  # Increment counter for each packet
  print(f"\nPacket number {packet_count}\n")
  pkt.show()
  

pkt = sniff(iface='br-6d579396a370', filter='net 8.8.0.0/16', prn=print_pkt)

# Print total packet count after sniffing stops
print(f"Total packets captured: {packet_count}")
