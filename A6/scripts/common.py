import os
import socket
import dpkt

# Specify PCAPs directory
PCAP_DIR = os.path.join(os.path.dirname(__file__), '..', 'pcaps')

# Locate GeoLite database with maxminddb_geolite2
try:
    import _maxminddb_geolite2, maxminddb

    GEOIP_PATH = os.path.join(os.path.dirname(_maxminddb_geolite2.__file__), 'GeoLite2-City.mmdb')
    GEOIP_READER = maxminddb.open_database(GEOIP_PATH)
except Exception:
    GEOIP_READER = None


def iter_packets():
    # Iterate over IP packets in PCAP files
    limit = int(os.environ.get("LIMIT_PACKETS", "0"))
    count = 0
    files = sorted([f for f in os.listdir(PCAP_DIR) if f.startswith('trace')])
    for fname in files:
        path = os.path.join(PCAP_DIR, fname)
        with open(path, 'rb') as f:
            pcap = dpkt.pcapng.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except (dpkt.UnpackError, dpkt.dpkt.NeedData):
                    continue
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                yield ts, eth.data
                count += 1
                if limit and count >= limit:
                    return

# Convert an IP address from bytes to string format
def ip_to_str(addr):
    return socket.inet_ntoa(addr)
