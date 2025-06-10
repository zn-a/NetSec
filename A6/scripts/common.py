import os
import socket
import dpkt

PCAP_DIR = os.path.join(os.path.dirname(__file__), '..', 'pcaps')

# Locate GeoLite database packaged with maxminddb_geolite2
try:
    import _maxminddb_geolite2, maxminddb
    GEOIP_PATH = os.path.join(os.path.dirname(_maxminddb_geolite2.__file__), 'GeoLite2-City.mmdb')
    GEOIP_READER = maxminddb.open_database(GEOIP_PATH)
except Exception:
    GEOIP_READER = None

def iter_packets():
    """Iterate over IP packets in telescope PCAP files.

    The optional environment variable ``LIMIT_PACKETS`` can be set to
    an integer to cap how many packets are yielded. This is useful when
    running in constrained environments or for quick testing.
    """
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

def ip_to_str(addr):
    return socket.inet_ntoa(addr)

