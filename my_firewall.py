#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import os

# A set to hold IP addresses we want to block
BLOCKED_IPS = {"1.1.1.1"} 

def process_packet(packet):
    """
    This function is called for each packet.
    """
    # Convert the raw packet to a Scapy packet
    scapy_packet = scapy.IP(packet.get_payload())

    # --- FIREWALL RULE ---
    # Block any outgoing packet with a destination IP in our block list
    if scapy_packet.haslayer(scapy.IP):
        # We check the DESTINATION of the packet
        if scapy_packet[scapy.IP].dst in BLOCKED_IPS:
            # I've updated the print message to be more accurate, too
            print(f"[+] Blocked outgoing packet to destination {scapy_packet[scapy.IP].dst}. Dropping.")
            packet.drop()
            return # Exit the function

    # If no block rule matched, accept the packet
    packet.accept()


# --- MAIN EXECUTION BLOCK ---
print("[+] Firewall starting up...")

# Create the queue object
queue = netfilterqueue.NetfilterQueue()

# Bind to queue 0 and set the callback function
queue.bind(0, process_packet)

try:
    # Start running the queue
    print("[+] Firewall is now running. Waiting for packets...")
    queue.run()
except KeyboardInterrupt:
    # This code runs if you press Ctrl+C
    print("\n[+] Firewall shutting down.")
    queue.unbind()

print("[+] Firewall stopped.")
