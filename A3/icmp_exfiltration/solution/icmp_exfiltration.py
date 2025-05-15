from scapy.all import *
from sys import argv
from Crypto.Cipher import AES


def check_usage():
    print("Usage:")
    print("Send mode: python3 icmp_exfiltration.py send <hex_key> <file_path> <dest_ip>")
    print("Receive mode: python3 icmp_exfiltration.py receive <hex_key> <output_file>")
    exit(1)


def main():
    # Check if the script is run with the correct number of arguments
    # and the correct mode (send or receive)
    if len(argv) < 2 or argv[1] not in ["send", "receive"]:
        check_usage()

    mode = argv[1]
    if mode == "send" and len(argv) != 5:
        check_usage()
    if mode == "receive" and len(argv) != 4:
        check_usage()

    print(f"Mode: {mode}")


if __name__ == "__main__":
    main()
