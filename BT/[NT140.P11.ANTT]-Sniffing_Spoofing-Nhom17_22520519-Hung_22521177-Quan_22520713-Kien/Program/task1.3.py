#!/usr/bin/env python3
from scapy.all import *

def traceroute(destination, max_hops=30, timeout=2):
    print(f"Traceroute to {destination} with a maximum of {max_hops} hops")
    for ttl in range(1, max_hops + 1):
    # Construct IP packet with increasing TTL
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        # Send the packet and wait for a response
        reply = sr1(packet, verbose=0, timeout=timeout)
        # Check if we got a reply
        if reply:
            print(f"{ttl} {reply.src}")
            # If the reply came from the destination, exit the loop
            if reply.src == destination:
                print("Reached destination.")
                break
        else:
            print(f"{ttl} *")
    print("Traceroute completed.")

traceroute('8.8.8.8')
