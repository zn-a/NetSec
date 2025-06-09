import dpkt
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
from common import iter_packets, ip_to_str

scanners = defaultdict(set)
for ts, ip in iter_packets():
    src = ip_to_str(ip.src)
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP) and tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            scanners[src].add(ip_to_str(ip.dst))
    elif ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        scanners[src].add(ip_to_str(ip.dst))

counts = Counter({s: len(dsts) for s, dsts in scanners.items()})

top = counts.most_common(10)
ips, nums = zip(*top)
plt.figure(figsize=(8,4))
plt.bar(range(len(ips)), nums)
plt.xticks(range(len(ips)), ips, rotation=45, ha='right')
plt.ylabel('Unique IPs scanned')
plt.title('Scope of Top Scanners')
plt.tight_layout()
plt.savefig('scanner_scope.png')
