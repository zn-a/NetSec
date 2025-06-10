from collections import Counter, defaultdict
import dpkt
from common import iter_packets, ip_to_str, GEOIP_READER
from pathlib import Path
import csv

counts = Counter()
for ts, ip in iter_packets():
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP) and tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            counts[ip_to_str(ip.src)] += 1
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
        if isinstance(ip.data, dpkt.udp.UDP):
            counts[ip_to_str(ip.src)] += 1

scanner, packets = counts.most_common(1)[0]

dest_ips = set()
ports = set()
for ts, ip in iter_packets():
    src = ip_to_str(ip.src)
    if src != scanner:
        continue
    if ip.p == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            dest_ips.add(ip_to_str(ip.dst))
            ports.add(tcp.dport)
    elif ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        dest_ips.add(ip_to_str(ip.dst))
        ports.add(ip.data.dport)

info = {'country': 'N/A'}
if GEOIP_READER:
    geo = GEOIP_READER.get(scanner)
    if geo and 'country' in geo:
        info['country'] = geo['country']['iso_code']

# Output setup
output_path = Path("output/heavy_hitter_scanner_output.csv")
output_path.parent.mkdir(exist_ok=True)

# Write to CSV
with open(output_path, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Field", "Value"])
    writer.writerow(["Scanner IP", scanner])
    writer.writerow(["Packets", packets])
    writer.writerow(["Destination IPs", len(dest_ips)])
    writer.writerow(["Ports", len(ports)])
    writer.writerow(["Country", info["country"]])

# Print table to terminal
print(f"Heavy Hitter Scanner: {scanner}")
print(f"Packets: {packets}")
print(f"Destination IPs: {len(dest_ips)}")
print(f"Ports: {len(ports)}")
print(f"Country: {info['country']}")
