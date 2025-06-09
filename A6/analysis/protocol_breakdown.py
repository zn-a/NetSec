from collections import Counter
import dpkt
import matplotlib.pyplot as plt
from common import iter_packets

counts = Counter()
for ts, ip in iter_packets():
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP) and tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            counts['TCP'] += 1
    elif ip.p == dpkt.ip.IP_PROTO_UDP:
        if isinstance(ip.data, dpkt.udp.UDP):
            counts['UDP'] += 1

labels = list(counts.keys())
values = [counts[l] for l in labels]
plt.figure(figsize=(4,4))
plt.pie(values, labels=labels, autopct='%1.1f%%')
plt.title('Protocol Breakdown')
plt.savefig('protocol_breakdown.png')
print('Protocol counts:', counts)
