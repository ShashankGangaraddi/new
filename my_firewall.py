#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import os

# A set to hold the IP addresses of known bad hosts
# We will manually add an IP to this set for testing
BLOCKED_IPS = {"1.1.1.1"} 

def process_packet(packet):
    """
    This function is called for each packet that the kernel sends to our queue.
    This is where all our firewall logic will go.
    """
    # Convert the raw packet data from the queue into a Scapy packet object
    # This makes it easy to read the packet's layers and fields
    scapy_packet = scapy.IP(packet.get_payload())

    # --- FIREWALL RULE LOGIC ---

    # Rule 1: Check if the packet is from a blocked IP address
    if scapy_packet.haslayer(scapy.IP):
        # scapy_packet[scapy.IP].src is the source IP address
        if scapy_packet[scapy.IP].src in BLOCKED_IPS:
            print(f"[+] Packet from blocked IP {scapy_packet[scapy.IP].src} found. Dropping packet.")
            # Drop the packet and stop processing it further
            packet.drop()
            return # Exit the function for this packet

    # Rule 2: Log all HTTP GET requests (for demonstration)
    # HTTP runs over TCP, usually on port 80
    if scapy_packet.haslayer(scapy.TCP) and scapy_packet[scapy.TCP].dport == 80:
        if scapy_packet.haslayer(scapy.Raw):
            # scapy.Raw contains the actual data payload of the packet
            payload = scapy_packet[scapy.Raw].load
            # Check if the payload contains the bytes for an HTTP GET request
            if b"GET" in payload:
                print(f"[*] Detected HTTP GET request from {scapy_packet[scapy.IP].src}")

    # --- HONEYPOT LOGIC (will be added here later) ---
    # For now, we will focus on the basic firewall.


    # --- DEFAULT VERDICT ---
    # If the packet did not match any of our drop rules, we let it pass.
    packet.accept()


# --- MAIN EXECUTION BLOCK ---
print("[+] Firewall starting up...")

# Create a NetfilterQueue object
queue = netfilterqueue.NetfilterQueue()

# Bind the queue object to queue number 0. 
# For every packet that goes into queue 0, call the 'process_packet' function.
# This is the core connection between the kernel and our script.
queue.bind(0, process_packet)

try:
    # Start running the queue. This will listen for packets indefinitely.
    print("[+] Firewall is now running. Waiting for packets...")
    queue.run()
except KeyboardInterrupt:
    # This code runs if you press Ctrl+C to stop the script
    print("\n[+] Firewall shutting down. Unbinding queue.")
    queue.unbind()

print("[+] Firewall stopped.")
