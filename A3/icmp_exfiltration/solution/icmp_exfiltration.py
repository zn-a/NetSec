from scapy.all import *
from sys import argv
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os


def usage():
    print("Usage:")
    print("Send mode:")
    print("  python3 icmp_exfiltration.py send <hex_key> <file_path> <destination_ip>")
    print("Receive mode:")
    print("  python3 icmp_exfiltration.py receive <hex_key> <output_file>")
    exit(1)


def init_cipher(hex_key, nonce):
    key = bytes.fromhex(hex_key)
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher


def main():
    if len(argv) < 2 or argv[1] not in ["send", "receive"]:
        usage()

    mode = argv[1]
    if mode == "send" and len(argv) != 5:
        usage()
    if mode == "receive" and len(argv) != 4:
        usage()

    # Placeholder: logic goes in next steps
    print(f"[*] Mode: {mode}")


if __name__ == "__main__":
    main()
