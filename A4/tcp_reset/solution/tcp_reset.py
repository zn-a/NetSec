from scapy.all import *
from sys import argv


def usage():
    print("Usage: python3 tcp_reset.py <src_ip> <dst_ip> <dst_port>")
    exit(1)


def main():
    if len(argv) != 4:
        usage()

    src_ip = argv[1]        # 192.168.124.20 (host2)
    dst_ip = argv[2]        # 192.168.124.10 (host1)
    dst_port = int(argv[3]) # dest port (1337)

    print(f"Executing TCP-reset attack: from {src_ip} to {dst_ip}:{dst_port}")


if __name__ == "__main__":
    main()
