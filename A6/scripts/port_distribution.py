import dpkt
import matplotlib.pyplot as plt
from collections import Counter
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

top_ports = tcp_ports.most_common(10)
ports, counts = zip(*top_ports)
plt.figure()
plt.bar(range(len(ports)), counts)
plt.xticks(range(len(ports)), ports)
plt.xlabel('Port')
plt.ylabel('Packets')
plt.title('Top 10 Scanned Ports (TCP)')
plt.savefig('port_distribution.png')
