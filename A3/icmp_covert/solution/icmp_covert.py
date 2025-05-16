from scapy.all import *
from sys import argv

def usage():
    print("Send mode: python3 icmp_covert.py send <dest_ip> <message>")
    print("Receive mode: python3 icmp_covert.py receive")
    exit(1)

def main():
    if len(argv) < 2 or argv[1] not in ["send", "receive"]:
        usage()

    mode = argv[1]

    if mode == "send" and len(argv) != 4:
        usage()
    if mode == "receive" and len(argv) != 2:
        usage()

    print(f"Mode: {mode}")

if __name__ == "__main__":
    main()
