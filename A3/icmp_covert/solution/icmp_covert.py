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

    if mode == "send":
        dest_ip = argv[2]
        message = argv[3]

        print(f"Destination IP: {dest_ip}")
        print(f"Message: {message}")

        data = message.encode()

        print(f"Sending message to {dest_ip}...")

        for i in range(0, len(data), 2):
            byte1 = data[i]
            byte2 = data[i+1]
            pkt = IP(dst=dest_ip) / ICMP(type=8, id=byte1, seq=byte2)
            send(pkt, verbose=False)

        print("Message sent")


if __name__ == "__main__":
    main()
