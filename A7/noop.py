from scapy.all import rdpcap, TCP, IP

packets = rdpcap("noop_hits.pcap")

for i, pkt in enumerate(packets):
    if pkt.haslayer(TCP):
        raw = bytes(pkt[TCP].payload)
        if b"A" * 31 in raw:
            print(f"Packet #{i+1}")
            print(f"{pkt[IP].src} -> {pkt[IP].dst}")
            print(f"Payload (snippet): {raw[:60]}")
            print("-" * 40)
