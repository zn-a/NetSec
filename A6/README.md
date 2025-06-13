# Assignment 6: Network Telescope Analysis

This folder contains the Python scripts used for Assignment 6 of CS4430 Network Security. A Python virtual environment `.venv` is used to manage dependencies.

## Setup instructions

```shell
# Create the virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install dpkt matplotlib maxminddb-geolite2
```

## Running the scripts (on Linux)

To run the assignment scripts, follow these steps:

1. **Extract the PCAP assignment files**: unzip the PCAP files into the `pcaps/` directory (already done).

2. **Activate the venv**:

   ```shell
   source .venv/bin/activate
   ```

3. **Run the scripts (from the root directory `A6/`)**.

### Data analysis scripts

- **Top Scanners**

  ```shell
  python3 scripts/top_scanners.py         # Execution time: 1m18s (timed using Linux `time` command)
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
  python3 scripts/heavy_hitter_scanner.py # 2m24s
  ```

### Visualization scripts

- **Time Series**

  ```shell
  python3 scripts/visualization/time_series.py        # 1m09s
  ```

- **Port Distribution**

  ```shell
  python3 scripts/visualization/port_distribution.py  # 1m14s
  ```

- **Scanner Scope**

  ```shell
  python3 scripts/visualization/scanner_scope.py      # 1m17s
  ```

All scripts assume that the PCAP files are located in `A6/pcaps`. The tree structure of the project is thus as follows:

```shell
tree -L 2
```

```shell
.
├── assignment_files
│   ├── trace1_00000_20240222190416.zip
│   ├── trace1_00001_20240222190651.zip
│   ├── trace1_00002_20240222190931.zip
│   ├── trace1_00003_20240222191206.zip
│   ├── trace1_00004_20240222191515.zip
│   ├── trace1_00005_20240222191820.zip
│   ├── trace2_00000_20240222191916.zip
│   ├── trace2_00001_20240222192217.zip
│   ├── trace2_00002_20240222192517.zip
│   ├── trace2_00003_20240222192816.zip
│   ├── trace2_00004_20240222193117.zip
│   └── trace2_00005_20240222193413.zip
├── Network_Security_Assignment__Telescope_2025.pdf
├── output
│   ├── heavy_hitter_scanner_output.csv
│   ├── protocol_breakdown_output.csv
│   ├── top_scanners_output.csv
│   └── top_target_ports_output.csv
├── pcaps
│   ├── trace1_00000_20240222190416
│   ├── trace1_00001_20240222190651
│   ├── trace1_00002_20240222190931
│   ├── trace1_00003_20240222191206
│   ├── trace1_00004_20240222191515
│   ├── trace1_00005_20240222191820
│   ├── trace2_00000_20240222191916
│   ├── trace2_00001_20240222192217
│   ├── trace2_00002_20240222192517
│   ├── trace2_00003_20240222192816
│   ├── trace2_00004_20240222193117
│   └── trace2_00005_20240222193413
├── README.md
├── report
│   ├── figures
│   ├── report.aux
│   ├── report.fdb_latexmk
│   ├── report.fls
│   ├── report.log
│   ├── report.out
│   ├── report.pdf
│   ├── report.synctex.gz
│   └── report.tex
└── scripts
    ├── common.py
    ├── heavy_hitter_scanner.py
    ├── protocol_breakdown.py
    ├── __pycache__
    ├── top_scanners.py
    ├── top_target_ports.py
    └── visualization
```

## PDF report

The PDF report is compiled from LaTeX using the command:

```shell
pdflatex -output-directory=report report/report.tex
```

The output will be saved as: `report/report.pdf` and the figures used are stored in `report/figures`.
