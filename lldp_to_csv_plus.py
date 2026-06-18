#!/usr/bin/env python3
"""
lldp_to_csv_plus.py

Export LLDP port-mapping info from a .pcapng capture to a CSV spreadsheet.
Designed for one-jack-at-a-time scanning, with optional append mode.

Columns:
  Jack, Switch, switchport, VLAN(s), LinkSpeed, Adapter, IPv4, PrefixLength, SubnetID, Gateway

No third-party Python modules required.

Examples:
  python lldp_to_csv_plus.py worklldp.pcapng -o portmap.csv --jack "Room 214 Jack A"
  python lldp_to_csv_plus.py worklldp.pcapng -o portmap.csv --jack "Room 214 Jack A" --append --adapter "Ethernet"
  python lldp_to_csv_plus.py worklldp.pcapng -o portmap.csv --jack-prefix "LPC-Test" --no-local
"""

import argparse
import csv
import ipaddress
import json
import os
import platform
import subprocess
import struct
from pathlib import Path

FIELDNAMES = [
    "Jack",
    "Switch",
    "switchport",
    "VLAN(s)",
    "LinkSpeed",
    "Adapter",
    "IPv4",
    "PrefixLength",
    "SubnetID",
    "Gateway",
]


def iter_pcapng_blocks(data):
    off = 0
    endian = "<"
    while off + 12 <= len(data):
        block_type = struct.unpack_from(endian + "I", data, off)[0]
        block_len = struct.unpack_from(endian + "I", data, off + 4)[0]

        if block_len < 12 or off + block_len > len(data):
            alt = ">" if endian == "<" else "<"
            block_type = struct.unpack_from(alt + "I", data, off)[0]
            block_len = struct.unpack_from(alt + "I", data, off + 4)[0]
            if block_len < 12 or off + block_len > len(data):
                break
            endian = alt

        body = data[off + 8 : off + block_len - 4]

        if block_type == 0x0A0D0D0A and len(body) >= 4:
            if struct.unpack_from("<I", body, 0)[0] == 0x1A2B3C4D:
                endian = "<"
            elif struct.unpack_from(">I", body, 0)[0] == 0x1A2B3C4D:
                endian = ">"

        yield block_type, body, endian
        off += block_len


def iter_packets_from_pcapng(path):
    data = Path(path).read_bytes()
    for block_type, body, endian in iter_pcapng_blocks(data):
        if block_type == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block
            _iface, _ts_hi, _ts_lo, cap_len, _orig_len = struct.unpack_from(
                endian + "IIIII", body, 0
            )
            yield body[20 : 20 + cap_len]
        elif block_type == 0x00000003 and len(body) >= 4:  # Simple Packet Block
            orig_len = struct.unpack_from(endian + "I", body, 0)[0]
            yield body[4 : 4 + orig_len]


def mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def clean_text(raw):
    text = raw.decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() else "" for ch in text).strip()


def parse_ethernet(packet):
    if len(packet) < 14:
        return None

    dst = mac(packet[0:6])
    src = mac(packet[6:12])
    ethertype = struct.unpack("!H", packet[12:14])[0]
    offset = 14

    # Skip 802.1Q / QinQ tags if present.
    while ethertype in (0x8100, 0x88A8, 0x9100) and len(packet) >= offset + 4:
        ethertype = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
        offset += 4

    return dst, src, ethertype, packet[offset:]


def decode_chassis_id(subtype, value):
    if subtype == 4 and len(value) >= 6:  # MAC address
        return mac(value[:6])
    return clean_text(value) or value.hex()


def decode_port_id(subtype, value):
    if subtype == 3 and len(value) >= 6:  # MAC address
        return mac(value[:6])
    return clean_text(value) or value.hex()


def decode_management_address(value):
    # Format: addr_len, addr_subtype, addr, iface_subtype, iface_num, oid_len, oid
    if len(value) < 2:
        return ""
    addr_len = value[0]
    if len(value) < 1 + addr_len:
        return ""
    addr = value[1 : 1 + addr_len]
    subtype = addr[0]
    addr_value = addr[1:]
    try:
        if subtype == 1 and len(addr_value) == 4:
            return str(ipaddress.IPv4Address(addr_value))
        if subtype == 2 and len(addr_value) == 16:
            return str(ipaddress.IPv6Address(addr_value))
    except ValueError:
        pass
    return addr_value.hex()


def add_vlan(vlans, vlan_id, name="", label=""):
    if vlan_id in (None, ""):
        return
    try:
        vlan_id = str(int(vlan_id))
    except ValueError:
        vlan_id = str(vlan_id)

    item = vlan_id
    if name:
        item = f"{item} ({name})"
    if label:
        item = f"{label}:{item}"
    if item not in vlans:
        vlans.append(item)


def parse_lldp(payload):
    result = {
        "switch": "",
        "switchport": "",
        "port_description": "",
        "chassis_id": "",
        "management_ip": "",
        "vlans": [],
    }

    offset = 0
    while offset + 2 <= len(payload):
        header = struct.unpack_from("!H", payload, offset)[0]
        offset += 2
        tlv_type = (header >> 9) & 0x7F
        tlv_len = header & 0x1FF
        value = payload[offset : offset + tlv_len]
        offset += tlv_len

        if tlv_type == 0:
            break

        if tlv_type == 1 and len(value) >= 1:  # Chassis ID
            result["chassis_id"] = decode_chassis_id(value[0], value[1:])

        elif tlv_type == 2 and len(value) >= 1:  # Port ID
            result["switchport"] = decode_port_id(value[0], value[1:])

        elif tlv_type == 4:  # Port Description
            result["port_description"] = clean_text(value)

        elif tlv_type == 5:  # System Name
            result["switch"] = clean_text(value)

        elif tlv_type == 8:  # Management Address
            result["management_ip"] = decode_management_address(value)

        elif tlv_type == 127 and len(value) >= 4:  # Organization-specific TLV
            oui = value[0:3]
            subtype = value[3]
            org_value = value[4:]

            # IEEE 802.1 VLAN TLVs. OUI 00:80:c2.
            if oui == b"\x00\x80\xc2":
                if subtype == 1 and len(org_value) >= 2:  # PVID
                    vlan_id = struct.unpack("!H", org_value[:2])[0]
                    add_vlan(result["vlans"], vlan_id, label="PVID")
                elif subtype == 2 and len(org_value) >= 3:  # PPVID
                    vlan_id = struct.unpack("!H", org_value[1:3])[0]
                    add_vlan(result["vlans"], vlan_id, label="PPVID")
                elif subtype == 3 and len(org_value) >= 3:  # VLAN Name
                    vlan_id = struct.unpack("!H", org_value[:2])[0]
                    name_len = org_value[2]
                    name = clean_text(org_value[3 : 3 + name_len])
                    add_vlan(result["vlans"], vlan_id, name=name, label="VLAN")

            # LLDP-MED/TIA TLVs. OUI 00:12:bb.
            elif oui == b"\x00\x12\xbb":
                if subtype == 2 and len(org_value) >= 4:  # Network Policy TLV
                    app_type = org_value[0]
                    network_policy_bits = struct.unpack("!H", org_value[1:3])[0]
                    vlan_id = network_policy_bits & 0x0FFF
                    if vlan_id:
                        add_vlan(result["vlans"], vlan_id, label=f"MED-app{app_type}")

    if not result["switch"]:
        result["switch"] = result["chassis_id"]
    if not result["switchport"]:
        result["switchport"] = result["port_description"]

    return result


def run_powershell_json(script):
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return {}
        return json.loads(completed.stdout)
    except Exception:
        return {}


def get_windows_local_network_info(adapter=None):
    """Return current Windows NIC info. This must be captured while plugged into the jack."""
    if platform.system().lower() != "windows":
        return {k: "" for k in ["LinkSpeed", "Adapter", "IPv4", "PrefixLength", "SubnetID", "Gateway"]}

    if adapter:
        adapter_literal = adapter.replace("'", "''")
        adapter_select = f"Get-NetAdapter -Name '{adapter_literal}' -ErrorAction SilentlyContinue"
        cfg_select = f"Get-NetIPConfiguration -InterfaceAlias '{adapter_literal}' -ErrorAction SilentlyContinue"
    else:
        adapter_select = "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.HardwareInterface -eq $true } | Select-Object -First 1"
        cfg_select = "$ad = " + adapter_select + "; if ($ad) { Get-NetIPConfiguration -InterfaceAlias $ad.Name -ErrorAction SilentlyContinue }"

    ps = rf"""
$ad = {adapter_select}
$cfg = {cfg_select}
$ipv4 = $null
$prefix = $null
$gw = $null
if ($cfg) {{
  $ipObj = $cfg.IPv4Address | Select-Object -First 1
  if ($ipObj) {{ $ipv4 = $ipObj.IPAddress; $prefix = $ipObj.PrefixLength }}
  $gwObj = $cfg.IPv4DefaultGateway | Select-Object -First 1
  if ($gwObj) {{ $gw = $gwObj.NextHop }}
}}
[pscustomobject]@{{
  Adapter = if ($ad) {{ $ad.Name }} else {{ "" }}
  LinkSpeed = if ($ad) {{ $ad.LinkSpeed }} else {{ "" }}
  IPv4 = if ($ipv4) {{ $ipv4 }} else {{ "" }}
  PrefixLength = if ($prefix -ne $null) {{ [string]$prefix }} else {{ "" }}
  Gateway = if ($gw) {{ $gw }} else {{ "" }}
}} | ConvertTo-Json -Compress
"""
    info = run_powershell_json(ps)
    if not isinstance(info, dict):
        info = {}

    ipv4 = info.get("IPv4") or ""
    prefix = info.get("PrefixLength") or ""
    subnet = ""
    try:
        if ipv4 and prefix != "":
            subnet = str(ipaddress.ip_network(f"{ipv4}/{prefix}", strict=False))
    except ValueError:
        subnet = ""

    return {
        "LinkSpeed": info.get("LinkSpeed", "") or "",
        "Adapter": info.get("Adapter", "") or "",
        "IPv4": ipv4,
        "PrefixLength": str(prefix) if prefix != "" else "",
        "SubnetID": subnet,
        "Gateway": info.get("Gateway", "") or "",
    }


def load_existing_keys(output_path):
    keys = set()
    if not Path(output_path).exists():
        return keys
    try:
        with open(output_path, "r", newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                keys.add((row.get("Jack", ""), row.get("Switch", ""), row.get("switchport", ""), row.get("VLAN(s)", "")))
    except Exception:
        pass
    return keys


def export_lldp(input_path, output_path, jack=None, jack_prefix="Jack", append=False, adapter=None, include_local=True):
    rows = []
    seen = set()
    existing = load_existing_keys(output_path) if append else set()
    row_num = len(existing)
    local_info = get_windows_local_network_info(adapter) if include_local else {k: "" for k in FIELDNAMES if k not in ["Jack", "Switch", "switchport", "VLAN(s)"]}

    for packet in iter_packets_from_pcapng(input_path):
        parsed_eth = parse_ethernet(packet)
        if not parsed_eth:
            continue

        _dst, _src, ethertype, payload = parsed_eth
        if ethertype != 0x88CC:  # LLDP
            continue

        info = parse_lldp(payload)
        vlans = "; ".join(info["vlans"])
        switch = info["switch"]
        switchport = info["switchport"]

        # Skip totally empty LLDP rows.
        if not any([switch, switchport, vlans]):
            continue

        key_no_jack = (switch, switchport, vlans)
        if key_no_jack in seen:
            continue
        seen.add(key_no_jack)

        row_num += 1
        jack_value = jack if jack else f"{jack_prefix} {row_num}"
        key_with_jack = (jack_value, switch, switchport, vlans)
        if key_with_jack in existing:
            continue

        row = {
            "Jack": jack_value,
            "Switch": switch,
            "switchport": switchport,
            "VLAN(s)": vlans,
        }
        row.update(local_info)
        rows.append(row)

    output_exists = Path(output_path).exists()
    mode = "a" if append and output_exists else "w"
    with open(output_path, mode, newline="", encoding="utf-8-sig") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=FIELDNAMES)
        if mode == "w":
            writer.writeheader()
        writer.writerows(rows)

    return rows


def main():
    parser = argparse.ArgumentParser(description="Export LLDP port-mapping fields to a CSV spreadsheet.")
    parser.add_argument("input", help="Input .pcapng file")
    parser.add_argument("-o", "--output", help="Output .csv file")
    parser.add_argument("--jack", help="Use this exact Jack value for all exported rows")
    parser.add_argument("--jack-prefix", default="Jack", help="Prefix used when auto-numbering Jack rows")
    parser.add_argument("--append", action="store_true", help="Append rows to an existing CSV instead of overwriting")
    parser.add_argument("--adapter", help="Windows adapter name, e.g. Ethernet. Used for LinkSpeed/subnet columns")
    parser.add_argument("--no-local", action="store_true", help="Do not add LinkSpeed/IP/subnet columns from Windows")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else input_path.with_suffix(".csv")

    rows = export_lldp(
        input_path,
        output_path,
        jack=args.jack,
        jack_prefix=args.jack_prefix,
        append=args.append,
        adapter=args.adapter,
        include_local=not args.no_local,
    )
    action = "Appended" if args.append else "Wrote"
    print(f"{action} {len(rows)} LLDP row(s) to {output_path}")


if __name__ == "__main__":
    main()
