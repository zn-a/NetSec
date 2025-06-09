from collections import Counter
import dpkt
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

print("Top 10 TCP Destination Ports")
for port, c in tcp_ports.most_common(10):
    print(f"{port},{c}")
print("\nTop 10 UDP Destination Ports")
for port, c in udp_ports.most_common(10):
    print(f"{port},{c}")
