import dpkt
import matplotlib.pyplot as plt
from collections import defaultdict
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common import iter_packets

bins = defaultdict(int)
start = None

# Count packets in 5-minute bins
for ts, ip in iter_packets():
    if start is None:
        start = ts
    bin_idx = int((ts - start) / 300)
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP) and tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            bins[bin_idx] += 1
    elif ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        bins[bin_idx] += 1

x = sorted(bins.keys())
y = [bins[i] for i in x]

# Plot setup
plt.figure()
plt.plot([i * 5 for i in x], y, marker='o')
plt.xlabel('Minutes')
plt.ylabel('Packets')
plt.title('Packet Count Over Time (5 min bins)')
plt.grid(True)
plt.savefig('report/figures/time_series.pdf')
