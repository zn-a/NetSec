from collections import Counter
import dpkt
from common import iter_packets, ip_to_str

counts = Counter()
for ts, ip in iter_packets():
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP) and tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            counts[ip_to_str(ip.src)] += 1
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
        if isinstance(ip.data, dpkt.udp.UDP):
            counts[ip_to_str(ip.src)] += 1

total = sum(counts.values())
print("Top 10 Scanners (by packet count)")
print("IP,Packets,Share")
for ip, c in counts.most_common(10):
    share = 100 * c / total if total else 0
    print(f"{ip},{c},{share:.2f}%")
