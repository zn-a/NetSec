from collections import Counter
import dpkt
import csv
from pathlib import Path
from common import iter_packets

tcp_ports = Counter()
udp_ports = Counter()

for ts, ip in iter_packets():
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP) and tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            tcp_ports[tcp.dport] += 1
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
        udp = ip.data
        if isinstance(udp, dpkt.udp.UDP):
            udp_ports[udp.dport] += 1

# Ensure output folder exists
output_path = Path("output/top_target_ports_output.csv")
output_path.parent.mkdir(exist_ok=True)

# Write combined CSV
with open(output_path, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Port", "Protocol", "Packets"])
    for port, count in tcp_ports.most_common(10):
        writer.writerow([port, "TCP", count])
    for port, count in udp_ports.most_common(10):
        writer.writerow([port, "UDP", count])

# Print formatted table to terminal
print("\nTop 10 TCP Destination Ports")
print(f"{'Port':<8}{'Packets':>10}")
for port, count in tcp_ports.most_common(10):
    print(f"{port:<8}{count:>10}")

print("\nTop 10 UDP Destination Ports")
print(f"{'Port':<8}{'Packets':>10}")
for port, count in udp_ports.most_common(10):
    print(f"{port:<8}{count:>10}")

print(f"\nResults saved to: {output_path}")
