#!/usr/bin/env python3
import argparse
import concurrent.futures as cf
import datetime
import ipaddress
import json
import socket
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
)

# ---- SNMP OIDs (extend as needed) -----------------------------------------

SNMP_OIDS = {
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "model": "1.3.6.1.2.1.47.1.1.1.1.13.1",
    "serial": "1.3.6.1.2.1.47.1.1.1.1.11.1",
}

# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Fast multithreaded network discovery + SNMP inventory"
    )
    # XML is now optional
    p.add_argument(
        "xml_file",
        nargs="?",
        help="XML file containing mod_ip_subnet_list entries (optional if --cidr used)",
    )
    p.add_argument(
        "--cidr",
        action="append",
        default=[],
        help="CIDR network to scan (can be used multiple times)",
    )
    p.add_argument(
        "-c", "--community", default="public", help="SNMP v2c community string"
    )
    p.add_argument(
        "-j", "--json", default="inventory.json", help="Output JSON inventory file"
    )
    p.add_argument(
        "--csv", default=None, help="Optional CSV output file (one shot export)"
    )
    p.add_argument(
        "-t",
        "--threads",
        type=int,
        default=128,
        help="Max concurrent worker threads (I/O bound)",
    )
    p.add_argument(
        "--ssh-timeout",
        type=float,
        default=0.75,
        help="Timeout (seconds) for SSH TCP pre-check",
    )
    p.add_argument(
        "--snmp-timeout",
        type=float,
        default=1.5,
        help="Timeout (seconds) for SNMP requests",
    )
    p.add_argument(
        "--snmp-retries",
        type=int,
        default=1,
        help="Retries for SNMP requests",
    )
    return p.parse_args()


# ---- XML parsing -----------------------------------------------------------

def iter_ips_from_xml(xml_path: Path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    for block in root.findall(".//mod_ip_subnet_list"):
        cidr = (block.findtext("ipsubnet_addr") or "").strip()
        name = (block.findtext("ipsubnet_name") or "").strip()
        start = (block.findtext("ipsubnet_start_addr") or "").strip()
        end = (block.findtext("ipsubnet_end_addr") or "").strip()

        if cidr and "/" in cidr:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                for ip in net.hosts():
                    yield str(ip), name, cidr
            except ValueError:
                continue
        elif start and end:
            try:
                start_ip = ipaddress.ip_address(start)
                end_ip = ipaddress.ip_address(end)
                current = start_ip
                while current <= end_ip:
                    yield str(current), name, f"{start}-{end}"
                    current += 1
            except ValueError:
                continue


# ---- CIDR parsing from CLI -------------------------------------------------

def iter_ips_from_cidrs(cidrs: list[str]):
    """
    Yield (ip_str, subnet_name, subnet_id) for each CLI-provided CIDR.
    """
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            print(f"Skipping invalid CIDR: {cidr}", file=sys.stderr)
            continue

        name = f"CLI {cidr}"
        for ip in net.hosts():
            yield str(ip), name, cidr


# ---- TCP pre-check (port 22) ----------------------------------------------

def ssh_port_open(ip: str, timeout: float = 0.75) -> bool:
    try:
        with socket.create_connection((ip, 22), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ---- SNMP helpers ----------------------------------------------------------

def snmp_get(ip: str, community: str, oid: str, timeout=1.5, retries=1):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # v2c
        UdpTransportTarget((ip, 161), timeout=timeout, retries=retries),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    except StopIteration:
        return None

    if errorIndication or errorStatus:
        return None

    for _, value in varBinds:
        return str(value.prettyPrint())
    return None


def poll_device(ip: str, subnet_name: str, subnet_id: str, community: str,
                snmp_timeout: float, snmp_retries: int) -> dict | None:
    if not ssh_port_open(ip, timeout=snmp_timeout):
        return None

    data = {"ip": ip, "source_subnet": subnet_id, "subnet_name": subnet_name}
    for field, oid in SNMP_OIDS.items():
        value = snmp_get(ip, community, oid, timeout=snmp_timeout, retries=snmp_retries)
        if value is not None:
            data[field] = value

    if "sysName" not in data and "sysDescr" not in data:
        return None

    data["last_seen"] = datetime.datetime.utcnow().isoformat() + "Z"
    return data


# ---- JSON / CSV helpers ----------------------------------------------------

def load_inventory(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_inventory(path: Path, inventory: dict):
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2, sort_keys=True)
    tmp.replace(path)


def export_csv(path: Path, inventory: dict):
    import csv

    if not inventory:
        return

    all_fields = set()
    for v in inventory.values():
        all_fields.update(v.keys())
    fieldnames = sorted(all_fields)

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for rec in sorted(inventory.values(), key=lambda r: r.get("ip", "")):
            writer.writerow(rec)


# ---- main ------------------------------------------------------------------

def main():
    args = parse_args()
    json_path = Path(args.json)
    csv_path = Path(args.csv) if args.csv else None

    if not args.xml_file and not args.cidr:
        print("You must provide an XML file and/or at least one --cidr.", file=sys.stderr)
        sys.exit(1)

    # preload inventory
    inventory = load_inventory(json_path)

    targets = []

    # From XML
    if args.xml_file:
        xml_path = Path(args.xml_file)
        if not xml_path.exists():
            print(f"XML not found: {xml_path}", file=sys.stderr)
            sys.exit(1)
        targets.extend(iter_ips_from_xml(xml_path))

    # From CLI CIDRs
    if args.cidr:
        targets.extend(iter_ips_from_cidrs(args.cidr))

    total_ips = len(targets)
    print(f"Loaded {total_ips} IPs from XML/CIDR")

    futures = []
    scanned = 0
    discovered = 0

    with cf.ThreadPoolExecutor(max_workers=args.threads) as executor:
        for ip, subnet_name, subnet_id in targets:
            future = executor.submit(
                poll_device,
                ip,
                subnet_name,
                subnet_id,
                args.community,
                args.snmp_timeout,
                args.snmp_retries,
            )
            futures.append(future)

        for future in cf.as_completed(futures):
            scanned += 1
            result = future.result()
            if result:
                discovered += 1
                inventory[result["ip"]] = result

            if scanned % 100 == 0 or scanned == total_ips:
                print(
                    f"\rScanned {scanned}/{total_ips} IPs, found {discovered} devices",
                    end="",
                    flush=True,
                )

    print()
    print(f"Finished. Total devices discovered/updated: {discovered}")

    save_inventory(json_path, inventory)
    print(f"Inventory JSON saved to {json_path}")

    if csv_path:
        export_csv(csv_path, inventory)
        print(f"CSV export saved to {csv_path}")


if __name__ == "__main__":
    main()
