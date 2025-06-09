# Network Telescope Analysis Scripts

This folder contains Python scripts used for Assignment 6 data analysis. A Python virtual environment is recommended. Install the required packages with:

```bash
python3 -m venv venv
source venv/bin/activate
pip install dpkt matplotlib maxminddb-geolite2
```

## Running the Scripts

1. **Extract PCAPs**: unzip the PCAP archives from `assignment_files/` into the `pcaps/` directory (already done).
2. **Top Scanners**
   ```bash
   python top_scanners.py
   ```
   Prints the ten IPs that send the most TCP SYN and UDP packets. Set
   `LIMIT_PACKETS` to process only a subset of data when resources are limited.
3. **Top Ports**
   ```bash
   python top_ports.py
   ```
   Shows the ten most targeted TCP and UDP destination ports.
   Set `LIMIT_PACKETS` as above for quick runs.
4. **Protocol Breakdown**
   ```bash
   python protocol_breakdown.py
   ```
   Generates a pie chart `protocol_breakdown.png` with TCP vs UDP share.
   Can use `LIMIT_PACKETS`.
5. **Heavy Hitter**
   ```bash
   python heavy_hitter.py
   ```
   Displays statistics for the scanner with the highest packet count and performs IP geolocation using the bundled GeoLite2 database. Obey `LIMIT_PACKETS` if defined.
6. **Visualization Scripts** (`time_series.py`, `port_distribution.py`, `scanner_scope.py`)
   Each script outputs a PNG figure used in the report. They also respect `LIMIT_PACKETS`.

All scripts assume the PCAP files are located in `../pcaps` relative to this directory.

## Report

`report/report.tex` compiles into `report.pdf` and includes the generated tables and figures.
