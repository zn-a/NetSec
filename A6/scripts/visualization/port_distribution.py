import dpkt
import matplotlib.pyplot as plt
from collections import Counter
import sys
import os
import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common import iter_packets

tcp_ports = Counter()
udp_ports = Counter()

for ts, ip in iter_packets():
    if ip.p == dpkt.ip.IP_PROTO_TCP:
        tcp = ip.data
        if isinstance(tcp, dpkt.tcp.TCP) and tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
            tcp_ports[tcp.dport] += 1
    elif ip.p == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
        udp_ports[ip.data.dport] += 1

# Top 10 ports for each protocol
tcp_top = tcp_ports.most_common(10)
udp_top = udp_ports.most_common(10)

# Prepare data
tcp_labels, tcp_counts = zip(*tcp_top)
udp_labels, udp_counts = zip(*udp_top)

labels = list(map(str, tcp_labels + udp_labels))
protocols = ['TCP'] * len(tcp_labels) + ['UDP'] * len(udp_labels)
counts = list(tcp_counts) + list(udp_counts)

x = np.arange(len(labels))  # label locations
colors = ['C0' if p == 'TCP' else 'C1' for p in protocols]

# Plotting
plt.figure(figsize=(12, 6))
bars = plt.bar(x, counts, color=colors)
plt.xticks(x, labels, rotation=45)
plt.xlabel('Port Number')
plt.ylabel('Packets')
plt.title('Top 10 Scanned Ports (TCP and UDP)')
plt.grid(axis='y')
plt.legend(handles=[
    plt.Rectangle((0, 0), 1, 1, color='C0', label='TCP'),
    plt.Rectangle((0, 0), 1, 1, color='C1', label='UDP')
])
plt.tight_layout()

# Save plot
fig_dir = "report/figures"
os.makedirs(fig_dir, exist_ok=True)
plt.savefig(os.path.join(fig_dir, "port_distribution.pdf"))
print("Saved combined TCP/UDP port distribution plot")
