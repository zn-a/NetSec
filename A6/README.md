# Assignment 6: Network Telescope Analysis

This folder contains Python scripts used for Assignment 6. A Python virtual environment `.venv` is used to manage
dependencies:

## Setup Instructions

```shell
# Create the virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install dpkt matplotlib maxminddb-geolite2
```

## Running the Scripts

1. **Extract PCAPs**: unzip the PCAP archives from `assignment_files/` into the `pcaps/` directory (already done).
2. **Activate the venv**:
   ```shell
   source .venv/bin/activate
   ```
3. **Run the scripts (from root directory `A6/`)**:

    - **Top Scanners**
      ```shell
      python3 scripts/top_scanners.py         # 1m18s
      ```
    - **Top Target Ports**
      ```shell
      python3 scripts/top_target_ports.py     # 1m17s
      ```
    - **Protocol Breakdown**
      ```shell
      python3 scripts/protocol_breakdown.py   # 1m16s
      ```
    - **Heavy Hitter Scanner**
      ```shell
      python3 scripts/heavy_hitter_scanner.py # XXmXXs
      ```
    - **Visualization Scripts** (`time_series.py`, `port_distribution.py`, `scanner_scope.py`)
      Each script outputs a PNG figure used in the report. They also respect `LIMIT_PACKETS`.

All scripts assume the PCAP files are located in `../pcaps` relative to this directory.

## PDF Report

The PDF report is compiled from LaTeX using the command:

```shell
pdflatex -output-directory=report report/report.tex
```

The output will be saved as: `report/report.pdf`.
