from collections import Counter
import dpkt
import csv
from pathlib import Path
from common import iter_packets, ip_to_str

# Count TCP SYNs and UDP packets
counts = Counter()
for ts, ip in iter_packets():
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP) and tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            counts[ip_to_str(ip.src)] += 1
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
        if isinstance(ip.data, dpkt.udp.UDP):
            counts[ip_to_str(ip.src)] += 1

# Output setup
total = sum(counts.values())
top_10 = counts.most_common(10)
output_path = Path("output/top_scanners_output.csv")
output_path.parent.mkdir(exist_ok=True)

# Write to CSV
with open(output_path, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["IP", "Packets", "Share"])
    for ip, count in top_10:
        share = 100 * count / total if total else 0
        writer.writerow([ip, count, f"{share:.2f}%"])

# Print nicely formatted table to terminal
print("Top 10 Scanners (by packet count)\n")
print(f"{'IP':<20}\t{'Packets':>8}\t{'Share':>6}")
for ip, count in top_10:
    share = 100 * count / total if total else 0
    print(f"{ip:<20}\t{count:>8}\t{share:>5.2f}%")
