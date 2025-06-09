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
      python3 data_analysis/top_scanners.py
      ```
      Prints the ten IPs that send the most TCP SYN and UDP packets. Set
      `LIMIT_PACKETS` to process only a subset of data when resources are limited.
    - **Top Ports**
      ```shell
      python3 data_analysis/top_target_ports.py
      ```
      Shows the ten most targeted TCP and UDP destination ports.
      Set `LIMIT_PACKETS` as above for quick runs.
    - **Protocol Breakdown**
      ```shell
      python3 data_analysis/protocol_breakdown.py
      ```
      Generates a pie chart `protocol_breakdown.png` with TCP vs UDP share.
      Can use `LIMIT_PACKETS`.
    - **Heavy Hitter**
      ```shell
      python3 data_analysis/heavy_hitter_scanner.py
      ```
      Displays statistics for the scanner with the highest packet count and performs IP geolocation using the bundled
      GeoLite2 database. Obey `LIMIT_PACKETS` if defined.
    - **Visualization Scripts** (`time_series.py`, `port_distribution.py`, `scanner_scope.py`)
      Each script outputs a PNG figure used in the report. They also respect `LIMIT_PACKETS`.

All scripts assume the PCAP files are located in `../pcaps` relative to this directory.

## PDF Report

The PDF report is compiled from LaTeX using the command:

```shell
pdflatex -output-directory=report report/report.tex
```

The output will be saved as: `report/report.pdf`.
