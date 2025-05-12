from scapy.all import *
from sys import argv
import sys
import requests


def main():
    if len(argv) != 4:
        print("Usage: python3 spoof_ip.py <target_ip> <spoofed_ip> <payload_length>")
        sys.exit(1)

    target_ip = sys.argv[1]
    spoofed_ip = sys.argv[2]
    payload_len = int(sys.argv[3])

    # Set the interface
    payload = b"A" * payload_len

    # Create the packet
    packet = IP(src=spoofed_ip, dst=target_ip) / ICMP()

    # Send the packet
    send(packet, count=2, verbose=0)

    print(f"Target IP: {target_ip}")
    print(f"Spoofed IP: {spoofed_ip}")
    print(f"Payload Length: {payload_len}")


if __name__ == "__main__":
    main()
