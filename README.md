# Network Device Discovery

This script performs fast, multithreaded network discovery with optional XML- or CIDR-provided target lists and captures basic SNMP inventory details.

## Installation

Use the official [pysnmp](https://github.com/pysnmp/pysnmp) package for SNMP access:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run the script by pointing it at an XML file containing `mod_ip_subnet_list` entries and/or supplying one or more `--cidr` arguments:

```bash
python network_discovery.py devices.xml --cidr 10.0.0.0/24 --cidr 192.168.1.0/24 \
  --community public --json inventory.json --csv inventory.csv
```

The script saves the consolidated inventory to JSON and can also emit a one-off CSV export when `--csv` is supplied.
