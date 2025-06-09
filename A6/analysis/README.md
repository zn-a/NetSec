# Network Telescope Analysis Scripts

This folder contains Python scripts used for Assignment 6 data analysis. The scripts require Python 3 with the `dpkt` and `maxminddb-geolite2` packages installed. Install dependencies using:

```bash
pip install dpkt maxminddb-geolite2
```

### Running the Scripts

1. **Extract PCAPs**: unzip all archives from `Assignment Files/` into `A6/pcaps` (already done in the repo).
2. **Top Scanners**
   ```bash
   python top_scanners.py
   ```
   Prints the ten IPs that send the most TCP SYN and UDP packets.
3. **Top Ports**
   ```bash
   python top_ports.py
   ```
   Shows the ten most targeted TCP and UDP destination ports.
4. **Protocol Breakdown**
   ```bash
   python protocol_breakdown.py
   ```
   Generates a pie chart `protocol_breakdown.png` with TCP vs UDP share.
5. **Heavy Hitter**
   ```bash
   python heavy_hitter.py
   ```
   Displays statistics for the scanner with the highest packet count and performs IP geolocation using the bundled GeoLite2 database.
6. **Visualization Scripts** (`time_series.py`, `port_distribution.py`, `scanner_scope.py`)
   Each script outputs a PNG figure used in the report.

All scripts assume the PCAP files are located in `../pcaps` relative to this directory.
