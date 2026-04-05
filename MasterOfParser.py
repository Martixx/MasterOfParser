#!/usr/bin/env python3
"""
MasterOfParser
==============
Parsea logs raw de PaloAlto (LEEF 2.0) y Fortinet exportados desde QRadar,
los normaliza a CIM y los cruza con los resultados del IOCsOfSpades.
Detecta el formato automáticamente por línea — ficheros mixtos OK.

Flujo recomendado:
  1. Extraer IPs únicas del log:
       python FW_Log_Parser.py "todo marzo.csv" --extract-ips ips_para_iocs.txt
  2. Meter ips_para_iocs.txt en IOCsOfSpades → genera ULTRA CSV
  3. Enriquecer el CIM con el resultado:
       python FW_Log_Parser.py "todo marzo.csv" --ioc-csv 20260401-1741_ULTRA.csv
  4. Solo hits IOC:
       python FW_Log_Parser.py "todo marzo.csv" --ioc-csv 20260401-1741_ULTRA.csv --ioc-only

Salida: CSV CIM con BOM UTF-8 (compatible con Excel directamente).
"""

import csv
import calendar
import re
import sys
import os
import argparse
import threading
import queue
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timedelta

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    _HAS_TK = True
except ImportError:
    _HAS_TK = False

try:
    import matplotlib

    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    _HAS_MPL = True
except ImportError:
    _HAS_MPL = False

# ─────────────────────────────────────────────────────────────────────────────
# Mapeo LEEF key → campo CIM
# ─────────────────────────────────────────────────────────────────────────────
LEEF_TO_CIM = {
    # Tiempo
    "devTime": "timestamp",
    # Red - origen
    "src": "src_ip",
    "srcPostNAT": "src_ip_nat",
    "srcPort": "src_port",
    "SourceZone": "src_zone",
    "SrcHostname": "src_host",
    "vSrcName": "src_host",
    "SrcMac": "src_mac",
    "IngressInterface": "inbound_interface",
    # Red - destino
    "dst": "dest_ip",
    "dstPostNAT": "dest_ip_nat",
    "dstPort": "dest_port",
    "DestinationZone": "dest_zone",
    "DstHostname": "dest_host",
    "DstMac": "dest_mac",
    "EgressInterface": "outbound_interface",
    # Protocolo / Aplicación
    "proto": "transport",
    "Application": "app",
    "URLCategory": "url_category",
    # Tráfico
    "srcBytes": "bytes_out",
    "dstBytes": "bytes_in",
    "totalBytes": "bytes_total",
    "srcPackets": "packets_out",
    "dstPackets": "packets_in",
    "totalPackets": "packets_total",
    "ElapsedTime": "duration",
    # Usuario
    "usrName": "user",
    "SourceUser": "user",
    "SrcUser": "user",
    "DestinationUser": "dest_user",
    # Acción (QRadar exporta el EventID numérico en group4; la acción real viene en KV)
    "act": "action",
    # Regla / Política
    "RuleName": "rule",
    "RuleUUID": "rule_uuid",
    "ActionSource": "action_source",
    "SessionEndReason": "session_end_reason",
    # Dispositivo
    "DeviceName": "dvc",
    "SerialNumber": "dvc_serial",
    "VirtualSystem": "virtual_system",
    "Subtype": "subtype",
    "SrcDeviceOS": "src_os",
    # Sesión
    "SessionID": "session_id",
    "RepeatCount": "repeat_count",
    "Flags": "flags",
    "sequence": "sequence",
    # Threat intelligence (EDL, DAG, etc.)
    "SrcEDL": "src_edl",
    "DstEDL": "dest_edl",
    "SrcDAG": "src_dag",
    "DstDAG": "dest_dag",
}

# ─────────────────────────────────────────────────────────────────────────────
# Mapeo Fortinet key → campo CIM
# ─────────────────────────────────────────────────────────────────────────────
PROTO_MAP = {"1": "icmp", "6": "tcp", "17": "udp", "58": "ipv6-icmp"}

FORTINET_TO_CIM = {
    # Dispositivo
    "devname": "dvc",
    "devid": "dvc_serial",
    "subtype": "subtype",
    "vd": "virtual_system",
    # Origen
    "srcip": "src_ip",
    "srcname": "src_host",
    "srcport": "src_port",
    "srcintf": "inbound_interface",
    "srcmac": "src_mac",
    "srccountry": "src_country",
    # Destino
    "dstip": "dest_ip",
    "dstport": "dest_port",
    "dstintf": "outbound_interface",
    "dstmac": "dest_mac",
    "dstcountry": "dest_country",
    # Protocolo / App
    "service": "app",
    "app": "app",  # UTM: sobreescribe service con la app detectada (más específica)
    "appcat": "url_category",
    # Acción / Regla
    "action": "action",
    "policyname": "rule",
    "poluuid": "rule_uuid",
    "sessionid": "session_id",
    # Tráfico
    "sentbyte": "bytes_out",
    "rcvdbyte": "bytes_in",
    "sentpkt": "packets_out",
    "rcvdpkt": "packets_in",
    "duration": "duration",
    # Endpoint info (muy útil en Fortinet)
    "osname": "src_os",
    "srcosname": "src_os",
    "srcssid": "src_zone",
    # Usuario autenticado (VPN/SSL-VPN/auth)
    "user": "user",
    "srcuser": "user",
    "unauthuser": "user",
    "xauthuser": "user",
    # UTM: hostname destino (webfilter, app-ctrl)
    "hostname": "dest_host",
    "dstname": "dest_host",
    # UTM webfilter: URL accedida
    "url": "url",
}

# Columnas CIM de salida (orden para Excel)
CIM_COLUMNS = [
    # ── Tiempo ─────────────────────────────────────────────────────────────
    "timestamp",
    "timestamp_date",
    # ── Dispositivo ────────────────────────────────────────────────────────
    "dvc",
    "dvc_serial",
    "vendor",
    "subtype",
    # ── Acción ─────────────────────────────────────────────────────────────
    "action",
    "action_source",
    "rule",
    "rule_uuid",
    "session_end_reason",
    # ── Origen ─────────────────────────────────────────────────────────────
    "src_ip",
    "src_ip_nat",
    "src_port",
    "src_zone",
    "src_host",
    "src_mac",
    "inbound_interface",
    "user",
    # ── Destino ────────────────────────────────────────────────────────────
    "dest_ip",
    "dest_ip_nat",
    "dest_port",
    "dest_zone",
    "dest_host",
    "dest_mac",
    "outbound_interface",
    "dest_user",
    # ── Protocolo / App ────────────────────────────────────────────────────
    "transport",
    "app",
    "url_category",
    "url",
    # ── Tráfico ────────────────────────────────────────────────────────────
    "bytes_out",
    "bytes_in",
    "bytes_total",
    "packets_out",
    "packets_in",
    "packets_total",
    "duration",
    # ── Sesión ─────────────────────────────────────────────────────────────
    "session_id",
    "repeat_count",
    "virtual_system",
    "flags",
    "sequence",
    "src_edl",
    "dest_edl",
    "src_dag",
    "dest_dag",
    # ── Geo (Fortinet) ──────────────────────────────────────────────────────
    "src_country",
    "dest_country",
    # ── Endpoint OS (Fortinet) ──────────────────────────────────────────────
    "src_os",
    # ── IOC enrichment src ─────────────────────────────────────────────────
    "ioc_src",
    "ioc_src_risk",
    "ioc_src_country",
    "ioc_src_owner",
    "ioc_src_asn",
    "ioc_src_reputation",
    "ioc_src_malicious",
    "ioc_src_vendors",
    "ioc_src_cluster",
    "ioc_src_source",
    "ioc_src_vt_vendor",
    "ioc_src_osint_hits",
    "ioc_src_osint_sources",
    # ── IOC enrichment dst ─────────────────────────────────────────────────
    "ioc_dst",
    "ioc_dst_risk",
    "ioc_dst_country",
    "ioc_dst_owner",
    "ioc_dst_asn",
    "ioc_dst_reputation",
    "ioc_dst_malicious",
    "ioc_dst_vendors",
    "ioc_dst_cluster",
    "ioc_dst_source",
    "ioc_dst_vt_vendor",
    "ioc_dst_osint_hits",
    "ioc_dst_osint_sources",
    "raw_event",
]


def _get_output_columns(include_raw_event: bool = False) -> list[str]:
    if include_raw_event:
        return list(CIM_COLUMNS)
    return [col for col in CIM_COLUMNS if col != "raw_event"]


# Regex LEEF 2.0: captura vendor, product, version, eventid, delimiter y KV
_LEEF_RE = re.compile(
    r"LEEF:2\.0\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|[^|]*\|(.*)", re.DOTALL
)

# Regex Fortinet: extrae pares key=value (valores quoted o unquoted)
_FORTINET_KV_RE = re.compile(r'(\w+)=("(?:[^"]*)"|\S+)')

# Cisco FTD 313005: extrae interfaces, IPs ICMP y payload original
_CISCO_FTD_ICMP_RE = re.compile(
    r"%FTD-\d+-313005:.*?icmp\s+src\s+([^:\s]+):([0-9.]+)\s+dst\s+([^:\s]+):([0-9.]+).*?"
    r"Original\s+IP\s+payload:\s+(\w+)\s+src\s+([0-9.]+)/([0-9]+)\s+dst\s+([0-9.]+)/([0-9]+)",
    re.IGNORECASE | re.DOTALL,
)


# ─────────────────────────────────────────────────────────────────────────────
# Parsing LEEF (PaloAlto)
# ─────────────────────────────────────────────────────────────────────────────
def parse_leef_line(line: str) -> dict | None:
    """Parsea una línea LEEF 2.0 (PaloAlto) y devuelve un dict CIM."""
    m = _LEEF_RE.search(line)
    if not m:
        return None

    vendor = m.group(1).strip()  # "Palo Alto Networks"
    leef_event_id = m.group(4).strip()  # Puede ser "allow" o un cód. numérico QRadar
    kv_part = m.group(5)  # "cat=TRAFFIC|devTime=...|src=..."

    record: dict = {"vendor": vendor}

    for pair in kv_part.split("|"):
        if "=" in pair:
            key, _, val = pair.partition("=")
            cim_key = LEEF_TO_CIM.get(key.strip())
            if cim_key:
                record[cim_key] = val.strip()

    # Si el KV no aportó acción, usar el EventID del header solo si no es numérico
    if not record.get("action"):
        record["action"] = leef_event_id if not leef_event_id.isdigit() else ""

    # Normalización: Fortinet/otros usan "accept" → estandarizar a "allow"
    _ACTION_NORM = {
        "accept": "allow",
        "permitted": "allow",
        "blocked": "deny",
        "dropped": "drop",
        "reset": "reset-both",
    }
    record["action"] = _ACTION_NORM.get(
        record.get("action", "").lower(), record.get("action", "")
    )

    return record


# ─────────────────────────────────────────────────────────────────────────────
# Parsing Fortinet (syslog KV)
# ─────────────────────────────────────────────────────────────────────────────
def parse_fortinet_line(line: str) -> dict | None:
    """Parsea una línea de log Fortinet (space-separated key=value) → dict CIM."""
    normalized_line = line.strip()
    if normalized_line.startswith('"') and normalized_line.endswith('"'):
        normalized_line = normalized_line[1:-1]
    normalized_line = normalized_line.replace('""', '"')

    kv: dict = {}
    for m in _FORTINET_KV_RE.finditer(normalized_line):
        key = m.group(1)
        val = m.group(2).strip('"')
        kv[key] = val

    # Procesamos tráfico y también eventos UTM con src/dst para no perder visibilidad.
    if not kv.get("srcip") or not kv.get("dstip"):
        return None

    record: dict = {"vendor": "Fortinet"}

    # Timestamp combinado de date + time
    date_val = kv.get("date", "")
    time_val = kv.get("time", "")
    if date_val and time_val:
        record["timestamp"] = f"{date_val} {time_val}"

    for fort_key, cim_key in FORTINET_TO_CIM.items():
        val = kv.get(fort_key, "")
        if val:
            record[cim_key] = val

    # Protocolo numérico → texto
    proto_raw = kv.get("proto", "")
    record["transport"] = PROTO_MAP.get(proto_raw, proto_raw)

    # Zona origen: prioridad srcssid (WiFi) > srcintf
    if not record.get("src_zone"):
        record["src_zone"] = kv.get("srcintf", "")

    if not record.get("dest_zone"):
        record["dest_zone"] = kv.get("dstintf", "")

    if not record.get("bytes_total"):
        record["bytes_total"] = str(
            int(_safe_float(kv.get("sentbyte"))) + int(_safe_float(kv.get("rcvdbyte")))
        )

    if not record.get("packets_total"):
        record["packets_total"] = str(
            int(_safe_float(kv.get("sentpkt"))) + int(_safe_float(kv.get("rcvdpkt")))
        )

    # Normalizar acción: accept→allow, blocked→deny, etc.
    _ACTION_NORM = {
        "accept": "allow",
        "permitted": "allow",
        "blocked": "deny",
        "dropped": "drop",
        "reset": "reset-both",
    }
    record["action"] = _ACTION_NORM.get(
        record.get("action", "").lower(), record.get("action", "")
    )

    return record


# ─────────────────────────────────────────────────────────────────────────────
# Parsing Cisco FTD (syslog text)
# ─────────────────────────────────────────────────────────────────────────────
def parse_cisco_ftd_line(line: str) -> dict | None:
    """Parsea eventos Cisco FTD tipo 313005 (ICMP error con payload original)."""
    normalized_line = line.strip()
    if normalized_line.startswith('"') and normalized_line.endswith('"'):
        normalized_line = normalized_line[1:-1]
    normalized_line = normalized_line.replace('""', '"')

    m = _CISCO_FTD_ICMP_RE.search(normalized_line)
    if not m:
        return None

    src_if = m.group(1).strip()
    icmp_src_ip = m.group(2).strip()
    dst_if = m.group(3).strip()
    icmp_dst_ip = m.group(4).strip()
    transport = m.group(5).strip().lower()
    payload_src_ip = m.group(6).strip()
    payload_src_port = m.group(7).strip()
    payload_dst_ip = m.group(8).strip()
    payload_dst_port = m.group(9).strip()

    record: dict = {
        "vendor": "Cisco",
        "subtype": "ftd-313005",
        "action": "no-matching-connection",
        # Usamos el payload original como flujo principal para análisis coherente.
        "src_ip": payload_src_ip,
        "src_port": payload_src_port,
        "dest_ip": payload_dst_ip,
        "dest_port": payload_dst_port,
        "transport": transport,
        "inbound_interface": src_if,
        "outbound_interface": dst_if,
        "src_zone": src_if,
        "dest_zone": dst_if,
        "session_end_reason": f"icmp_error src={icmp_src_ip} dst={icmp_dst_ip}",
    }
    return record


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher: auto-detecta formato por línea
# ─────────────────────────────────────────────────────────────────────────────
def parse_line(line: str) -> dict | None:
    """Detecta si la línea es LEEF, Fortinet o Cisco FTD y la parsea."""
    if "LEEF:2.0" in line:
        return parse_leef_line(line)
    if "srcip=" in line and "dstip=" in line:
        return parse_fortinet_line(line)
    if "%FTD-" in line and "Original IP payload:" in line:
        return parse_cisco_ftd_line(line)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Carga de IOCs
# ─────────────────────────────────────────────────────────────────────────────
def load_ioc_list(path: str) -> set:
    """Carga una lista plana de IPs (una por línea) en un set."""
    iocs: set = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            ip = line.strip()
            if ip and not ip.startswith("#"):
                iocs.add(ip)
    return iocs


def load_iocs_csv(path: str) -> dict:
    """
    Carga un CSV de IOCsOfSpades (ULTRA / DOMAINS) en un dict { ip -> row }.
    Gestiona celdas multilínea (whois) con csv.DictReader.
    """
    ioc_map: dict = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ip", "").strip()
            if ip:
                ioc_map[ip] = row
    return ioc_map


def load_osint_csv(path: str) -> dict:
    """Carga un CSV OSINT en un dict { ip -> row } para fusionarlo con VT."""
    osint_map: dict = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ip", "").strip()
            if ip:
                osint_map[ip] = row
    return osint_map


def merge_ioc_maps(vt_map: dict, osint_map: dict) -> dict:
    """Fusiona VT + OSINT por IP, guardando columnas OSINT con prefijo osint_."""
    merged: dict = {}
    all_ips = set(vt_map.keys()) | set(osint_map.keys())
    for ip in all_ips:
        row: dict = {}
        vt_row = vt_map.get(ip)
        os_row = osint_map.get(ip)
        if vt_row:
            row.update(vt_row)
        if os_row:
            for key, value in os_row.items():
                if key == "ip":
                    continue
                row[f"osint_{key}"] = value
        row["ip"] = ip
        merged[ip] = row
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# Enriquecimiento IOC
# ─────────────────────────────────────────────────────────────────────────────
_IOC_SUFFIX = [
    "",
    "_risk",
    "_country",
    "_owner",
    "_asn",
    "_reputation",
    "_malicious",
    "_vendors",
    "_cluster",
    "_source",
    "_vt_vendor",
    "_osint_hits",
    "_osint_sources",
]


def _empty_ioc(prefix: str) -> dict:
    return {f"ioc_{prefix}{s}": "" for s in _IOC_SUFFIX}


def _to_int(value) -> int:
    try:
        return int(float(str(value or "0").strip()))
    except ValueError:
        return 0


def _truthy(value) -> bool:
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "y", "si", "s"}


def _pick_source(row: dict) -> str:
    osint_verdict = str(row.get("osint_verdict", "")).strip().lower()
    if osint_verdict in {"malicious", "suspicious"}:
        return "OSINT verdict"

    vendors = str(row.get("vendors_malicious", "")).strip()
    if vendors:
        return "VirusTotal"
    if _truthy(row.get("is_vpn")):
        return "VPN intelligence"
    if str(row.get("cluster_flag", "")).strip():
        return "Heuristics cluster"
    if str(row.get("c2_suspect", "")).strip():
        return "C2 heuristic"

    osint_hits = _to_int(row.get("osint_bl_dshield_targets"))
    if osint_hits > 0:
        return "OSINT blocklists"

    return "IOCsofSpades"


def _pick_vt_vendor(row: dict) -> str:
    vendors = str(row.get("vendors_malicious", "")).strip()
    if not vendors:
        return ""
    # vendors_malicious suele venir como CSV/lista de engines
    first = vendors.split(",")[0].split(";")[0].strip()
    return first


def _has_osint_positive(row: dict) -> bool:
    verdict = str(row.get("osint_verdict", "")).strip().lower()
    if verdict in {"malicious", "suspicious"}:
        return True

    if str(row.get("osint_asn_drop", "")).strip().lower() == "yes":
        return True

    bool_flags = [
        "osint_bl_dshield_24",
        "osint_bl_blocklistde_48h",
        "osint_bl_feodo",
        "osint_bl_cinsscore",
        "osint_bl_et_compromised",
        "osint_abuseipdb_is_tor",
    ]
    for key in bool_flags:
        if str(row.get(key, "")).strip().lower() == "yes":
            return True

    numeric_fields = [
        "osint_bl_dshield_targets",
        "osint_abuseipdb_score",
        "osint_abuseipdb_reports",
        "osint_threatfox_confidence",
        "osint_urlhaus_url_count",
        "osint_otx_pulses",
    ]
    for key in numeric_fields:
        if _to_int(row.get(key)) > 0:
            return True

    malware_name = str(row.get("osint_threatfox_malware", "")).strip()
    if malware_name and "error:" not in malware_name.lower():
        return True

    return False


def _collect_osint_sources(row: dict) -> list[str]:
    sources: list[str] = []

    if str(row.get("osint_asn_drop", "")).strip().lower() == "yes":
        source = str(row.get("osint_asn_drop_source", "")).strip()
        sources.append(source or "asn_drop")

    if (
        str(row.get("osint_bl_dshield_24", "")).strip().lower() == "yes"
        or _to_int(row.get("osint_bl_dshield_targets")) > 0
    ):
        sources.append("dshield")
    if str(row.get("osint_bl_blocklistde_48h", "")).strip().lower() == "yes":
        sources.append("blocklistde")
    if str(row.get("osint_bl_feodo", "")).strip().lower() == "yes":
        sources.append("feodo")
    if str(row.get("osint_bl_cinsscore", "")).strip().lower() == "yes":
        sources.append("cinsscore")
    if str(row.get("osint_bl_et_compromised", "")).strip().lower() == "yes":
        sources.append("et_compromised")

    if (
        _to_int(row.get("osint_abuseipdb_score")) > 0
        or _to_int(row.get("osint_abuseipdb_reports")) > 0
    ):
        sources.append("abuseipdb")
    if (
        _to_int(row.get("osint_threatfox_confidence")) > 0
        or str(row.get("osint_threatfox_malware", "")).strip()
    ):
        malware = str(row.get("osint_threatfox_malware", "")).strip().lower()
        if "error:" not in malware:
            sources.append("threatfox")
    if _to_int(row.get("osint_urlhaus_url_count")) > 0:
        sources.append("urlhaus")
    if _to_int(row.get("osint_otx_pulses")) > 0:
        sources.append("otx")

    # Mantener orden y eliminar duplicados
    unique = []
    seen = set()
    for source in sources:
        if source and source not in seen:
            seen.add(source)
            unique.append(source)
    return unique


def _is_ioc_alert(row: dict | None) -> bool:
    if not row:
        return False
    if _has_osint_positive(row):
        return True
    if _to_int(row.get("malicious")) > 0:
        return True
    if _to_int(row.get("suspicious")) > 0:
        return True
    if str(row.get("vendors_malicious", "")).strip():
        return True
    if _truthy(row.get("cluster_flag")):
        return True
    if _truthy(row.get("c2_suspect")):
        return True
    if _to_int(row.get("risk_score")) >= 70:
        return True
    return False


def enrich_ioc(ip: str, ioc_set: set, ioc_map: dict, prefix: str) -> dict:
    """Devuelve campos de enriquecimiento IOC para una IP dada."""
    result = _empty_ioc(prefix)
    if not ip:
        return result

    in_list = ip in ioc_set
    row = ioc_map.get(ip)

    if row:
        result[f"ioc_{prefix}_risk"] = row.get("risk_score", "")
        result[f"ioc_{prefix}_country"] = row.get("country", "")
        result[f"ioc_{prefix}_owner"] = row.get("owner", "")
        result[f"ioc_{prefix}_asn"] = row.get("asn_full", row.get("asn", ""))
        result[f"ioc_{prefix}_reputation"] = row.get("reputation", "")
        result[f"ioc_{prefix}_malicious"] = row.get("malicious", "")
        result[f"ioc_{prefix}_vendors"] = row.get("vendors_malicious", "")
        result[f"ioc_{prefix}_cluster"] = row.get("cluster_flag", "")
        result[f"ioc_{prefix}_source"] = _pick_source(row)
        result[f"ioc_{prefix}_vt_vendor"] = _pick_vt_vendor(row)
        osint_sources = _collect_osint_sources(row)
        result[f"ioc_{prefix}_osint_sources"] = ",".join(osint_sources)
        result[f"ioc_{prefix}_osint_hits"] = str(len(osint_sources))

    # IOC YES solo cuando hay señal maliciosa, no solo por aparecer en el ULTRA.
    if _is_ioc_alert(row):
        result[f"ioc_{prefix}"] = "YES"
    elif in_list:
        result[f"ioc_{prefix}"] = "NO"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Constantes para la pestaña Análisis
# ─────────────────────────────────────────────────────────────────────────────
_NO_SECONDARY_FIELD = "(ninguno)"
_NO_FILTER_FIELD = "(sin filtro)"
_NO_SERIES_FIELD = "(total)"
_ANALYSIS_VENDOR_OPTIONS = ["(todos)", "Palo Alto Networks", "Fortinet", "Cisco"]
_PIVOT_FIELDS = [
    "vendor",
    "timestamp",
    "timestamp_date",
    "action",
    "action_source",
    "rule",
    "session_end_reason",
    "src_ip",
    "src_ip_nat",
    "src_port",
    "src_zone",
    "src_host",
    "src_mac",
    "src_country",
    "src_os",
    "dest_ip",
    "dest_ip_nat",
    "dest_port",
    "dest_zone",
    "dest_host",
    "dest_mac",
    "dest_country",
    "transport",
    "app",
    "url_category",
    "url",
    "user",
    "dest_user",
    "dvc",
    "dvc_serial",
    "rule_uuid",
    "virtual_system",
    "inbound_interface",
    "outbound_interface",
    "session_id",
    "ioc_src_country",
    "ioc_dst_country",
    "ioc_src_risk",
    "ioc_dst_risk",
    "ioc_src_owner",
    "ioc_dst_owner",
    "ioc_src_reputation",
    "ioc_dst_reputation",
    "ioc_src_malicious",
    "ioc_dst_malicious",
    "ioc_src_vendors",
    "ioc_dst_vendors",
    "ioc_src_source",
    "ioc_dst_source",
    "ioc_src_vt_vendor",
    "ioc_dst_vt_vendor",
    "ioc_src_osint_hits",
    "ioc_dst_osint_hits",
    "ioc_src_osint_sources",
    "ioc_dst_osint_sources",
]
_DERIVED_ANALYSIS_FIELDS = [
    "traffic_scope",
    "ioc_scope",
    "dest_port_band",
    "src_port_band",
]
_PIVOT_METRICS = [
    "Recuento",
    "Suma bytes_total",
    "Suma bytes_out",
    "Suma bytes_in",
    "Suma packets_total",
]
_ANOMALY_BUCKETS = ["Hora", "Día", "Semana", "Mes"]
_ANOMALY_METRICS = ["Recuento", "Suma bytes_total", "Suma bytes_in", "Suma bytes_out"]
_CHART_TYPES = [
    "Barras horizontales",
    "Barras verticales",
    "Quesito (pie)",
    "Donut",
    "Línea",
]
_CHART_COLORS = [
    "#377eb8",
    "#e41a1c",
    "#4daf4a",
    "#984ea3",
    "#ff7f00",
    "#a65628",
    "#f781bf",
    "#999999",
    "#1b9e77",
    "#d95f02",
    "#7570b3",
    "#e7298a",
    "#66a61e",
    "#e6ab02",
    "#a6761d",
    "#666666",
    "#8dd3c7",
    "#fb8072",
    "#bebada",
    "#80b1d3",
]
_TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%Y/%m/%d",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d/%m/%Y",
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M",
    "%d-%m-%Y",
    "%b %d %Y %H:%M:%S",
    "%b %d %H:%M:%S",
]


def _safe_float(value) -> float:
    text = str(value or "").strip().replace(",", "")
    if not text:
        return 0.0
    try:
        return float(text)
    except ValueError:
        return 0.0


def _parse_timestamp(raw_value: str) -> datetime | None:
    text = str(raw_value or "").strip()
    if not text:
        return None

    if text.isdigit():
        try:
            raw_int = int(text)
            if raw_int > 10**12:
                return datetime.fromtimestamp(raw_int / 1000)
            if raw_int > 10**9:
                return datetime.fromtimestamp(raw_int)
        except (OverflowError, OSError, ValueError):
            pass

    iso_candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso_candidate)
        return parsed.replace(tzinfo=None)
    except ValueError:
        pass

    for fmt in _TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=datetime.now().year)
            return parsed
        except ValueError:
            continue

    return None


def _safe_int(value) -> int:
    return int(_safe_float(value))


def _first_non_empty(record: dict, keys: list[str]) -> str:
    for key in keys:
        value = str(record.get(key, "") or "").strip()
        if value:
            return value
    return ""


def unify_cim_record(record: dict, forti_src_zone_mode: str = "ssid") -> dict:
    """Consolida aliases/sinónimos en campos CIM canónicos."""
    if not record:
        return record

    # Alias frecuentes para el mismo significado en distintas fuentes.
    alias_candidates = {
        "src_ip_nat": ["src_ip_nat", "src_nat_ip", "srcPostNAT"],
        "dest_ip_nat": ["dest_ip_nat", "dst_nat_ip", "dstPostNAT"],
        "src_zone": ["src_zone", "SourceZone", "srcintf", "inbound_interface"],
        "dest_zone": ["dest_zone", "DestinationZone", "dstintf", "outbound_interface"],
        "src_host": ["src_host", "SrcHostname", "srcname", "hostname"],
        "dest_host": ["dest_host", "DstHostname", "dstname"],
        "user": ["user", "usrName", "SourceUser", "SrcUser", "srcuser", "xauthuser"],
        "rule": ["rule", "RuleName", "policyname", "policy_name"],
        "rule_uuid": ["rule_uuid", "RuleUUID", "poluuid"],
    }

    for canonical_key, candidates in alias_candidates.items():
        if not str(record.get(canonical_key, "") or "").strip():
            record[canonical_key] = _first_non_empty(record, candidates)

    # En Fortinet, src_zone puede representar SSID o interfaz física/lógica.
    # Permitimos forzar interfaz para alinearlo con reportes operativos.
    if record.get("vendor") == "Fortinet" and forti_src_zone_mode == "interface":
        inbound_interface = str(record.get("inbound_interface", "") or "").strip()
        if inbound_interface:
            record["src_zone"] = inbound_interface

    # Fecha derivada para análisis/export sin componente horaria.
    timestamp_value = str(record.get("timestamp", "") or "").strip()
    if timestamp_value and not str(record.get("timestamp_date", "") or "").strip():
        parsed_ts = _parse_timestamp(timestamp_value)
        if parsed_ts is not None:
            record["timestamp_date"] = parsed_ts.strftime("%Y-%m-%d")

    # Si faltan los totales, derivarlos de in/out para mantener consistencia CIM.
    if not str(record.get("bytes_total", "") or "").strip():
        bytes_total = _safe_int(record.get("bytes_in")) + _safe_int(
            record.get("bytes_out")
        )
        if bytes_total > 0:
            record["bytes_total"] = str(bytes_total)

    if not str(record.get("packets_total", "") or "").strip():
        packets_total = _safe_int(record.get("packets_in")) + _safe_int(
            record.get("packets_out")
        )
        if packets_total > 0:
            record["packets_total"] = str(packets_total)

    return record


def _is_private_ip(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        return ipaddress.ip_address(text).is_private
    except ValueError:
        return False


def _port_band(value) -> str:
    port = _safe_int(value)
    if port <= 0:
        return "(vacío)"
    if port <= 1023:
        return "well-known"
    if port <= 49151:
        return "registered"
    return "dynamic"


def _truncate_label(value: str, max_len: int = 28) -> str:
    text = str(value or "")
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _floor_timestamp(dt: datetime, bucket: str) -> datetime:
    if bucket == "Mes":
        return dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if bucket == "Semana":
        return (dt - timedelta(days=dt.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    if bucket == "Día":
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    return dt.replace(minute=0, second=0, microsecond=0)


def _format_bucket(dt: datetime, bucket: str) -> str:
    if bucket == "Mes":
        return dt.strftime("%Y-%m")
    if bucket == "Semana":
        return dt.strftime("Sem %Y-%m-%d")
    if bucket == "Día":
        return dt.strftime("%Y-%m-%d")
    return dt.strftime("%Y-%m-%d %H:00")


def _detect_spikes(
    series: list[tuple[datetime, float]],
) -> tuple[float, float, float, list[dict]]:
    if not series:
        return 0.0, 0.0, 0.0, []

    values = [value for _, value in series]
    mean_value = sum(values) / len(values)
    variance = sum((value - mean_value) ** 2 for value in values) / len(values)
    std_value = variance**0.5
    threshold = max(mean_value * 1.5, mean_value + (2 * std_value))

    peaks = []
    for bucket_dt, value in series:
        z_score = 0.0 if std_value == 0 else (value - mean_value) / std_value
        if value >= threshold and value > 0:
            severity = "Alta" if z_score >= 3 else "Media"
            peaks.append(
                {
                    "bucket_dt": bucket_dt,
                    "value": value,
                    "z_score": z_score,
                    "severity": severity,
                }
            )

    peaks.sort(key=lambda item: item["value"], reverse=True)
    return mean_value, std_value, threshold, peaks


# ─────────────────────────────────────────────────────────────────────────────
# GUI (tkinter) — se lanza cuando no hay argumentos en línea de comandos
# ─────────────────────────────────────────────────────────────────────────────
class MasterOfParserGUI:
    def __init__(self, root: "tk.Tk"):
        self.root = root
        root.title("🤘 MasterOfParser")
        root.geometry("960x680")
        root.resizable(True, True)

        # ── Logo programático (tkinter Canvas, 0 RAM extra) ──────────────────
        self._set_window_icon(root)

        self._queue: queue.Queue = queue.Queue()
        self._last_output: str = ""

        # ── Header con logo inline ───────────────────────────────────────────
        header = tk.Frame(root, bg="#1a1a1a", height=44)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        self._draw_header_logo(header)

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=(4, 8))
        self._nb = nb

        self._tab_parser = ttk.Frame(nb)
        self._tab_results = ttk.Frame(nb)
        self._tab_analysis = ttk.Frame(nb)
        self._tab_histograms = ttk.Frame(nb)
        nb.add(self._tab_parser, text="  Parser  ")
        nb.add(self._tab_results, text="  Resultados  ")
        nb.add(self._tab_analysis, text="  Análisis  ")
        nb.add(self._tab_histograms, text="  Histogramas  ")

        self._build_parser_tab()
        self._build_results_tab()
        self._build_analysis_tab()
        self._build_histograms_tab()

    # ── Logo / icono ─────────────────────────────────────────────────────────
    def _set_window_icon(self, root):
        """Icono de ventana: rayo dorado 16×16 dibujado con PhotoImage."""
        try:
            img = tk.PhotoImage(width=16, height=16)
            # Fondo negro
            img.put("#1a1a1a", to=(0, 0, 16, 16))
            # Rayo dorado (forma de zigzag vertical)
            bolt = [
                (8, 1),
                (9, 1),
                (10, 1),
                (11, 1),
                (7, 2),
                (8, 2),
                (9, 2),
                (10, 2),
                (6, 3),
                (7, 3),
                (8, 3),
                (9, 3),
                (5, 4),
                (6, 4),
                (7, 4),
                (8, 4),
                (4, 5),
                (5, 5),
                (6, 5),
                (7, 5),
                (8, 5),
                (9, 5),
                (10, 5),
                (11, 5),
                (12, 5),
                (3, 6),
                (4, 6),
                (5, 6),
                (6, 6),
                (7, 6),
                (8, 6),
                (9, 6),
                (10, 6),
                (11, 6),
                (6, 7),
                (7, 7),
                (8, 7),
                (9, 7),
                (5, 8),
                (6, 8),
                (7, 8),
                (8, 8),
                (4, 9),
                (5, 9),
                (6, 9),
                (7, 9),
                (3, 10),
                (4, 10),
                (5, 10),
                (6, 10),
                (2, 11),
                (3, 11),
                (4, 11),
                (5, 11),
            ]
            for x, y in bolt:
                img.put("#f0b429", to=(x, y))
            root.iconphoto(True, img)
            self._icon_img = img  # evitar GC
        except Exception:
            pass  # Si falla (algunos WM) no es crítico

    def _draw_header_logo(self, parent):
        """Header oscuro con logo canvas + nombre de app."""
        # Canvas para el logo (rayo + M estilizada)
        c = tk.Canvas(parent, width=200, height=44, bg="#1a1a1a", highlightthickness=0)
        c.pack(side="left", padx=(12, 0))

        # Rayo dorado (polígono)
        c.create_polygon(
            28,
            4,
            38,
            4,
            30,
            22,
            40,
            22,
            18,
            42,
            26,
            24,
            16,
            24,
            fill="#f0b429",
            outline="#c8960a",
            width=1,
        )
        # Nombre app
        c.create_text(
            52,
            14,
            text="MasterOf",
            anchor="w",
            font=("Segoe UI", 13, "bold"),
            fill="#ffffff",
        )
        c.create_text(
            52, 30, text="Parser", anchor="w", font=("Segoe UI", 11), fill="#f0b429"
        )

        # Subtítulo / tagline derecha
        tk.Label(
            parent,
            text="🤘  Firewall Log Intelligence",
            bg="#1a1a1a",
            fg="#888888",
            font=("Segoe UI", 9),
        ).pack(side="left", padx=16)

    # ── Pestaña Parser ───────────────────────────────────────────────────────
    def _build_parser_tab(self):
        tab = self._tab_parser
        pad = {"padx": 8, "pady": 4}

        # Log de entrada
        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        ttk.Label(row, text="Log de entrada *", width=20, anchor="w").pack(side="left")
        self._log_var = tk.StringVar()
        ttk.Entry(row, textvariable=self._log_var, width=58).pack(side="left", padx=4)
        ttk.Button(row, text="Examinar…", command=self._pick_log).pack(side="left")

        # IOC CSV
        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        ttk.Label(row, text="IOC CSV (ULTRA)", width=20, anchor="w").pack(side="left")
        self._ioc_var = tk.StringVar()
        ttk.Entry(row, textvariable=self._ioc_var, width=58).pack(side="left", padx=4)
        ttk.Button(row, text="Examinar…", command=self._pick_ioc).pack(side="left")

        # OSINT CSV
        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        ttk.Label(row, text="OSINT CSV", width=20, anchor="w").pack(side="left")
        self._osint_var = tk.StringVar()
        ttk.Entry(row, textvariable=self._osint_var, width=58).pack(side="left", padx=4)
        ttk.Button(row, text="Examinar…", command=self._pick_osint).pack(side="left")

        # Fichero de salida
        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        ttk.Label(row, text="Fichero de salida", width=20, anchor="w").pack(side="left")
        self._out_var = tk.StringVar()
        ttk.Entry(row, textvariable=self._out_var, width=58).pack(side="left", padx=4)
        ttk.Button(row, text="Guardar como…", command=self._pick_out).pack(side="left")

        # Extraer IPs
        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        self._extract_var = tk.BooleanVar()
        ttk.Checkbutton(
            row, text="Extraer IPs únicas a:", variable=self._extract_var
        ).pack(side="left")
        self._extract_path_var = tk.StringVar()
        ttk.Entry(row, textvariable=self._extract_path_var, width=40).pack(
            side="left", padx=4
        )
        ttk.Button(row, text="Guardar como…", command=self._pick_extract).pack(
            side="left"
        )

        # IOC only
        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        self._ioconly_var = tk.BooleanVar()
        ttk.Checkbutton(
            row, text="Solo filas con hit IOC (--ioc-only)", variable=self._ioconly_var
        ).pack(side="left")

        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        self._raw_event_var = tk.BooleanVar()
        ttk.Checkbutton(
            row,
            text="Incluir raw_event (más pesado; útil para depuración)",
            variable=self._raw_event_var,
        ).pack(side="left")

        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        ttk.Label(row, text="Forti src_zone", width=20, anchor="w").pack(side="left")
        self._forti_src_zone_mode_var = tk.StringVar(value="ssid")
        ttk.Combobox(
            row,
            textvariable=self._forti_src_zone_mode_var,
            values=["ssid", "interface"],
            width=12,
            state="readonly",
        ).pack(side="left", padx=4)
        ttk.Label(
            row,
            text="ssid = nombre WiFi, interface = CORP-WIFI/GUEST-WIFI",
        ).pack(side="left")

        ttk.Separator(tab, orient="horizontal").pack(fill="x", padx=8, pady=6)

        # Botones
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", padx=8)
        self._run_btn = ttk.Button(btn_frame, text="▶  Ejecutar", command=self._run)
        self._run_btn.pack(side="left")
        self._open_results_btn = ttk.Button(
            btn_frame,
            text="Ver resultados →",
            state="disabled",
            command=self._open_results_tab,
        )
        self._open_results_btn.pack(side="left", padx=8)

        # Barra de progreso
        self._progress = ttk.Progressbar(tab, mode="indeterminate")
        self._progress.pack(fill="x", padx=8, pady=4)

        # Consola
        ttk.Label(tab, text="Log de ejecución:", anchor="w").pack(fill="x", padx=8)
        console_frame = ttk.Frame(tab)
        console_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._console = tk.Text(
            console_frame,
            state="disabled",
            height=12,
            bg="#1e1e1e",
            fg="#d4d4d4",
            font=("Consolas", 9),
            wrap="none",
        )
        vsb = ttk.Scrollbar(
            console_frame, orient="vertical", command=self._console.yview
        )
        hsb = ttk.Scrollbar(
            console_frame, orient="horizontal", command=self._console.xview
        )
        self._console.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._console.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        console_frame.rowconfigure(0, weight=1)
        console_frame.columnconfigure(0, weight=1)

    # ── Pestaña Resultados ───────────────────────────────────────────────────
    def _build_results_tab(self):
        tab = self._tab_results

        # Controles superiores
        ctrl = ttk.Frame(tab)
        ctrl.pack(fill="x", padx=8, pady=6)
        ttk.Button(ctrl, text="Cargar CSV…", command=self._load_csv).pack(side="left")
        ttk.Separator(ctrl, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Label(ctrl, text="Filtrar:").pack(side="left")
        self._filter_var = tk.StringVar()
        filter_entry = ttk.Entry(ctrl, textvariable=self._filter_var, width=25)
        filter_entry.pack(side="left", padx=4)
        filter_entry.bind("<Return>", lambda _: self._add_result_filter())
        ttk.Label(ctrl, text="en columna:").pack(side="left")
        self._filter_col_var = tk.StringVar(value="(todas)")
        self._filter_col_cb = ttk.Combobox(
            ctrl,
            textvariable=self._filter_col_var,
            state="readonly",
            width=20,
        )
        self._filter_col_cb.pack(side="left", padx=4)
        ttk.Label(ctrl, text="Desde:").pack(side="left", padx=(8, 0))
        self._results_from_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._results_from_var, width=12).pack(
            side="left", padx=4
        )
        ttk.Button(
            ctrl,
            text="📅",
            width=3,
            command=lambda: self._open_calendar_popup(self._results_from_var),
        ).pack(side="left")
        ttk.Label(ctrl, text="Hasta:").pack(side="left", padx=(8, 0))
        self._results_to_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._results_to_var, width=12).pack(
            side="left", padx=4
        )
        ttk.Button(
            ctrl,
            text="📅",
            width=3,
            command=lambda: self._open_calendar_popup(self._results_to_var),
        ).pack(side="left")
        ttk.Button(ctrl, text="Añadir filtro", command=self._add_result_filter).pack(
            side="left"
        )
        ttk.Button(ctrl, text="Limpiar", command=self._clear_filter).pack(
            side="left", padx=4
        )
        ttk.Button(
            ctrl,
            text="→ Análisis",
            command=self._send_results_filters_to_analysis,
        ).pack(side="left", padx=(4, 0))

        chips_row = ttk.Frame(tab)
        chips_row.pack(fill="x", padx=8, pady=(0, 6))
        ttk.Label(chips_row, text="Filtros activos:").pack(side="left")
        self._results_filters_frame = ttk.Frame(chips_row)
        self._results_filters_frame.pack(side="left", fill="x", expand=True, padx=6)

        # Treeview con scroll doble
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self._tree = ttk.Treeview(tree_frame, show="headings", selectmode="browse")
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        # Menú contextual botón derecho
        self._ctx_menu = tk.Menu(self._tree, tearoff=0)
        self._tree.bind("<Button-3>", self._on_tree_rclick)

        # Barra de estado
        self._status_var = tk.StringVar(value="Sin datos cargados")
        ttk.Label(tab, textvariable=self._status_var, anchor="w").pack(
            fill="x", padx=8, pady=2
        )

        self._all_rows: list = []
        self._csv_columns: list = []
        self._sort_col: str = ""
        self._sort_asc: bool = True
        self._results_filters: list[dict] = []
        self._render_result_filter_chips()

    # ── Selectores de fichero ────────────────────────────────────────────────
    def _pick_log(self):
        p = filedialog.askopenfilename(
            title="Seleccionar log de entrada",
            filetypes=[("CSV / Log", "*.csv *.log *.txt"), ("Todos", "*.*")],
        )
        if p:
            self._log_var.set(p)

    def _pick_ioc(self):
        p = filedialog.askopenfilename(
            title="Seleccionar IOC CSV (ULTRA)",
            filetypes=[("CSV", "*.csv"), ("Todos", "*.*")],
        )
        if p:
            self._ioc_var.set(p)

    def _pick_osint(self):
        p = filedialog.askopenfilename(
            title="Seleccionar OSINT CSV",
            filetypes=[("CSV", "*.csv"), ("Todos", "*.*")],
        )
        if p:
            self._osint_var.set(p)

    def _pick_out(self):
        p = filedialog.asksaveasfilename(
            title="Guardar CSV de salida",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
        )
        if p:
            self._out_var.set(p)

    def _pick_extract(self):
        p = filedialog.asksaveasfilename(
            title="Guardar IPs únicas",
            defaultextension=".txt",
            filetypes=[("Texto", "*.txt"), ("Todos", "*.*")],
        )
        if p:
            self._extract_path_var.set(p)

    # ── Ejecución del parser ─────────────────────────────────────────────────
    def _log(self, msg: str):
        self._console.configure(state="normal")
        self._console.insert("end", msg + "\n")
        self._console.see("end")
        self._console.configure(state="disabled")

    def _run(self):
        log_file = self._log_var.get().strip()
        if not log_file:
            messagebox.showerror("Error", "Selecciona un fichero de log de entrada.")
            return
        if not os.path.isfile(log_file):
            messagebox.showerror("Error", f"No encontrado:\n{log_file}")
            return

        ioc_csv = self._ioc_var.get().strip() or None
        osint_csv = self._osint_var.get().strip() or None
        output_file = self._out_var.get().strip() or None
        ioc_only = self._ioconly_var.get()
        include_raw_event = self._raw_event_var.get()
        forti_src_zone_mode = self._forti_src_zone_mode_var.get().strip() or "ssid"
        extract_ips = (
            self._extract_path_var.get().strip() if self._extract_var.get() else None
        )

        if ioc_csv and not os.path.isfile(ioc_csv):
            messagebox.showerror("Error", f"IOC CSV no encontrado:\n{ioc_csv}")
            return
        if osint_csv and not os.path.isfile(osint_csv):
            messagebox.showerror("Error", f"OSINT CSV no encontrado:\n{osint_csv}")
            return

        self._run_btn.configure(state="disabled")
        self._open_results_btn.configure(state="disabled")
        self._progress.start(10)
        self._console.configure(state="normal")
        self._console.delete("1.0", "end")
        self._console.configure(state="disabled")

        threading.Thread(
            target=self._worker,
            args=(
                log_file,
                ioc_csv,
                osint_csv,
                output_file,
                ioc_only,
                extract_ips,
                include_raw_event,
                forti_src_zone_mode,
            ),
            daemon=True,
        ).start()
        self._poll()

    def _worker(
        self,
        log_file,
        ioc_csv,
        osint_csv,
        output_file,
        ioc_only,
        extract_ips,
        include_raw_event,
        forti_src_zone_mode,
    ):
        q = self._queue

        def log(msg):
            q.put(("log", msg))

        try:
            ioc_set: set = set()
            ioc_map: dict = {}
            vt_map: dict = {}
            osint_map: dict = {}

            if ioc_csv:
                vt_map = load_iocs_csv(ioc_csv)
                log(f"[+] IOC CSV:   {len(vt_map):,} IPs  ({ioc_csv})")
            if osint_csv:
                osint_map = load_osint_csv(osint_csv)
                log(f"[+] OSINT CSV: {len(osint_map):,} IPs  ({osint_csv})")

            if vt_map and osint_map:
                ioc_map = merge_ioc_maps(vt_map, osint_map)
                ioc_set = set(ioc_map.keys())
                log(f"[+] IOC merge: {len(ioc_map):,} IPs únicas (VT + OSINT)")
            elif vt_map:
                ioc_map = vt_map
                ioc_set = set(ioc_map.keys())
            elif osint_map:
                ioc_map = osint_map
                ioc_set = set(ioc_map.keys())

            ts = datetime.now().strftime("%Y%m%d-%H%M")
            output_file = output_file or f"{ts}_CIM_PARSED.csv"
            output_columns = _get_output_columns(include_raw_event)

            log(f"[+] Leyendo:   {log_file}")
            total_lines = sum(
                1 for _ in open(log_file, encoding="utf-8", errors="replace")
            )
            log(f"[+] Líneas:    {total_lines:,}")
            if include_raw_event:
                log("[+] raw_event: activado (salida más pesada)")
            log(f"[+] Forti src_zone: {forti_src_zone_mode}")

            parsed = 0
            skipped = 0
            ioc_hits = 0
            vendor_counts: Counter = Counter()
            ioc_hits_by_vendor: Counter = Counter()
            last_pct = -1
            unique_ips: set = set()

            with (
                open(log_file, encoding="utf-8", errors="replace") as fin,
                open(output_file, "w", newline="", encoding="utf-8-sig") as fout,
            ):
                writer = csv.DictWriter(
                    fout, fieldnames=output_columns, extrasaction="ignore"
                )
                writer.writeheader()

                for i, line in enumerate(fin, 1):
                    pct = (i * 100) // total_lines
                    if pct % 5 == 0 and pct != last_pct:
                        q.put(("progress", pct))
                        last_pct = pct

                    line = line.strip()
                    if not line:
                        continue

                    record = parse_line(line)
                    if not record:
                        skipped += 1
                        continue

                    record = unify_cim_record(record, forti_src_zone_mode)

                    vendor_name = record.get("vendor", "(sin_vendor)")
                    vendor_counts[vendor_name] += 1

                    src_ip = record.get("src_ip", "")
                    dest_ip = record.get("dest_ip", "")

                    if extract_ips:
                        if src_ip:
                            unique_ips.add(src_ip)
                        if dest_ip:
                            unique_ips.add(dest_ip)

                    record.update(enrich_ioc(src_ip, ioc_set, ioc_map, "src"))
                    record.update(enrich_ioc(dest_ip, ioc_set, ioc_map, "dst"))

                    has_ioc = (
                        record.get("ioc_src") == "YES" or record.get("ioc_dst") == "YES"
                    )
                    if has_ioc:
                        ioc_hits += 1
                        ioc_hits_by_vendor[vendor_name] += 1

                    if ioc_only and not has_ioc:
                        continue

                    if include_raw_event:
                        record["raw_event"] = line
                    writer.writerow(
                        {col: record.get(col, "") for col in output_columns}
                    )
                    parsed += 1

            if extract_ips and unique_ips:
                with open(extract_ips, "w", encoding="utf-8") as f:
                    for ip in sorted(unique_ips):
                        f.write(ip + "\n")
                log(f"[+] IPs únicas: {len(unique_ips):,}  →  {extract_ips}")

            log("─" * 50)
            log(f"[+] Procesados: {parsed + skipped:,}")
            log(f"[+] Exportados: {parsed:,} registros CIM")
            log(f"[+] Ignorados:  {skipped:,} líneas (formato no reconocido)")
            log(
                f"[+] IOC hits:   {ioc_hits:,} registros (src o dst con señal IOC maliciosa)"
            )
            if vendor_counts:
                summary_vendor = " | ".join(
                    f"{vendor}: {count:,}"
                    for vendor, count in vendor_counts.most_common()
                )
                log(f"[+] Fuentes:    {summary_vendor}")
            if ioc_hits_by_vendor:
                summary_ioc_vendor = " | ".join(
                    f"{vendor}: {count:,}"
                    for vendor, count in ioc_hits_by_vendor.most_common()
                )
                log(f"[+] IOC por fuente: {summary_ioc_vendor}")
            log(f"[+] Salida:     {output_file}")
            log("─" * 50)

            q.put(("done", output_file))

        except Exception as exc:
            q.put(("error", str(exc)))

    def _poll(self):
        try:
            while True:
                kind, data = self._queue.get_nowait()
                if kind == "log":
                    self._log(data)
                elif kind == "done":
                    self._last_output = data
                    self._progress.stop()
                    self._run_btn.configure(state="normal")
                    self._open_results_btn.configure(state="normal")
                    messagebox.showinfo("Listo", f"Fichero generado:\n{data}")
                    return
                elif kind == "error":
                    self._progress.stop()
                    self._run_btn.configure(state="normal")
                    messagebox.showerror("Error durante la ejecución", data)
                    return
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _open_results_tab(self):
        if self._last_output and os.path.isfile(self._last_output):
            self._load_csv(self._last_output)
        self._nb.select(self._tab_results)

    # ── Tabla de resultados ──────────────────────────────────────────────────
    def _load_csv(self, path: str = ""):
        if not path:
            path = filedialog.askopenfilename(
                title="Cargar CSV de resultados",
                filetypes=[("CSV", "*.csv"), ("Todos", "*.*")],
            )
        if not path or not os.path.isfile(path):
            return
        try:
            rows = []
            with open(path, encoding="utf-8-sig", errors="replace") as f:
                reader = csv.DictReader(f)
                cols = list(reader.fieldnames or [])
                for row in reader:
                    rows.append([row.get(c, "") for c in cols])

            self._csv_columns = cols
            self._all_rows = rows
            self._sort_col = ""
            self._sort_asc = True
            self._setup_tree(cols, rows)
            self._filter_col_cb["values"] = ["(todas)"] + cols
            self._filter_col_var.set("(todas)")
            self._filter_var.set("")
            self._results_from_var.set("")
            self._results_to_var.set("")
            self._results_filters = []
            self._render_result_filter_chips()
            # Actualizar combobox de columnas en la pestaña Análisis
            extra = [c for c in cols if c not in _PIVOT_FIELDS]
            analysis_fields = _DERIVED_ANALYSIS_FIELDS + _PIVOT_FIELDS + extra
            self._pivot_col_cb["values"] = analysis_fields
            self._pivot_secondary_col_cb["values"] = [
                _NO_SECONDARY_FIELD
            ] + analysis_fields
            self._analysis_filter1_field_cb["values"] = [
                _NO_FILTER_FIELD
            ] + analysis_fields
            self._analysis_filter2_field_cb["values"] = [
                _NO_FILTER_FIELD
            ] + analysis_fields
            self._hist_series_col_cb["values"] = [_NO_SERIES_FIELD] + analysis_fields
            self._hist_filter1_field_cb["values"] = [_NO_FILTER_FIELD] + analysis_fields
            self._hist_filter2_field_cb["values"] = [_NO_FILTER_FIELD] + analysis_fields
            if self._pivot_col_var.get() not in analysis_fields:
                self._pivot_col_var.set(analysis_fields[0] if analysis_fields else "")
            if (
                self._pivot_secondary_col_var.get()
                not in self._pivot_secondary_col_cb["values"]
            ):
                self._pivot_secondary_col_var.set(_NO_SECONDARY_FIELD)
            if (
                self._hist_series_col_var.get()
                not in self._hist_series_col_cb["values"]
            ):
                self._hist_series_col_var.set(_NO_SERIES_FIELD)
            if (
                self._hist_filter1_field_var.get()
                not in self._hist_filter1_field_cb["values"]
            ):
                self._hist_filter1_field_var.set(_NO_FILTER_FIELD)
            if (
                self._hist_filter2_field_var.get()
                not in self._hist_filter2_field_cb["values"]
            ):
                self._hist_filter2_field_var.set(_NO_FILTER_FIELD)
            self._status_var.set(
                f"{len(rows):,} filas  |  {len(cols)} columnas  |  {os.path.basename(path)}"
            )
        except Exception as exc:
            messagebox.showerror("Error cargando CSV", str(exc))

    def _setup_tree(self, cols, rows):
        tree = self._tree
        tree.delete(*tree.get_children())
        tree["columns"] = cols
        for col in cols:
            tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
            tree.column(col, width=max(len(col) * 8, 80), minwidth=60, stretch=False)
        for row in rows:
            tree.insert("", "end", values=row)

    def _open_calendar_popup(self, target_var: "tk.StringVar"):
        popup = tk.Toplevel(self.root)
        popup.title("Seleccionar fecha")
        popup.transient(self.root)
        popup.resizable(False, False)

        current = self._parse_time_bound(target_var.get()) or datetime.now()
        state = {"year": current.year, "month": current.month}

        header = ttk.Frame(popup)
        header.pack(fill="x", padx=8, pady=8)
        body = ttk.Frame(popup)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        def apply_date(day: int):
            target_var.set(f"{state['year']:04d}-{state['month']:02d}-{day:02d}")
            popup.destroy()

        def render():
            for child in header.winfo_children():
                child.destroy()
            for child in body.winfo_children():
                child.destroy()

            ttk.Button(header, text="<", width=3, command=lambda: move(-1)).pack(
                side="left"
            )
            ttk.Label(
                header,
                text=f"{calendar.month_name[state['month']]} {state['year']}",
                anchor="center",
            ).pack(side="left", fill="x", expand=True)
            ttk.Button(header, text=">", width=3, command=lambda: move(1)).pack(
                side="right"
            )

            for idx, name in enumerate(("Lu", "Ma", "Mi", "Ju", "Vi", "Sa", "Do")):
                ttk.Label(body, text=name, anchor="center", width=4).grid(
                    row=0, column=idx, padx=1, pady=1
                )

            month_matrix = calendar.Calendar(firstweekday=0).monthdayscalendar(
                state["year"], state["month"]
            )
            for row_idx, week in enumerate(month_matrix, start=1):
                for col_idx, day in enumerate(week):
                    if day == 0:
                        ttk.Label(body, text="", width=4).grid(
                            row=row_idx, column=col_idx, padx=1, pady=1
                        )
                    else:
                        ttk.Button(
                            body,
                            text=str(day),
                            width=4,
                            command=lambda d=day: apply_date(d),
                        ).grid(row=row_idx, column=col_idx, padx=1, pady=1)

        def move(delta: int):
            month = state["month"] + delta
            year = state["year"]
            if month < 1:
                month = 12
                year -= 1
            elif month > 12:
                month = 1
                year += 1
            state["month"] = month
            state["year"] = year
            render()

        render()
        popup.grab_set()

    def _format_result_filter_label(self, filter_item: dict) -> str:
        value = filter_item.get("value", "")
        field = filter_item.get("field", "(todas)")
        if value.startswith("!"):
            op = "≠"
            show_value = value[1:].strip()
        elif value.startswith("="):
            op = "="
            show_value = value[1:].strip()
        else:
            op = "≈"
            show_value = value
        return f"{field} {op} {show_value}"

    def _render_result_filter_chips(self):
        for child in self._results_filters_frame.winfo_children():
            child.destroy()
        if not self._results_filters:
            ttk.Label(
                self._results_filters_frame, text="(ninguno)", foreground="#777777"
            ).pack(side="left")
            return
        for idx, filter_item in enumerate(self._results_filters):
            chip = tk.Frame(
                self._results_filters_frame, bg="#e9eef8", bd=1, relief="solid"
            )
            chip.pack(side="left", padx=3, pady=2)
            tk.Label(
                chip,
                text=self._format_result_filter_label(filter_item),
                bg="#e9eef8",
                fg="#203050",
                padx=6,
            ).pack(side="left")
            tk.Button(
                chip,
                text="x",
                command=lambda i=idx: self._remove_result_filter(i),
                bd=0,
                bg="#e9eef8",
                fg="#8a1f1f",
                padx=4,
                pady=0,
            ).pack(side="left")

    def _add_result_filter(self):
        value = self._filter_var.get().strip()
        field = self._filter_col_var.get().strip()
        if not value:
            self._apply_filter()
            return
        self._results_filters.append({"field": field or "(todas)", "value": value})
        self._filter_var.set("")
        self._render_result_filter_chips()
        self._apply_filter()

    def _remove_result_filter(self, idx: int):
        if 0 <= idx < len(self._results_filters):
            del self._results_filters[idx]
        self._render_result_filter_chips()
        self._apply_filter()

    def _apply_filter(self):
        has_dates = bool(
            self._results_from_var.get().strip() or self._results_to_var.get().strip()
        )
        if not self._results_filters and not has_dates:
            self._setup_tree(self._csv_columns, self._all_rows)
            self._status_var.set(f"{len(self._all_rows):,} filas (sin filtro)")
            return

        filtered = []
        start_dt = self._parse_time_bound(
            self._results_from_var.get().strip(), is_end=False
        )
        end_dt = self._parse_time_bound(self._results_to_var.get().strip(), is_end=True)
        timestamp_idx = (
            self._csv_columns.index("timestamp")
            if "timestamp" in self._csv_columns
            else -1
        )

        for row in self._all_rows:
            ok = True
            for filter_item in self._results_filters:
                field = filter_item.get("field", "(todas)")
                value = filter_item.get("value", "")
                if field == "(todas)":
                    row_text = " | ".join(str(v) for v in row).lower()
                    test_value = str(value or "").strip()
                    if test_value.startswith("="):
                        cmp_value = test_value[1:].strip().lower()
                        if not any(str(v).lower() == cmp_value for v in row):
                            ok = False
                            break
                    elif test_value.startswith("!"):
                        cmp_value = test_value[1:].strip().lower()
                        if cmp_value in row_text:
                            ok = False
                            break
                    elif test_value.lower() not in row_text:
                        ok = False
                        break
                elif not self._apply_generic_filter(row, field, value):
                    ok = False
                    break
            if not ok:
                continue
            if start_dt or end_dt:
                if timestamp_idx < 0:
                    continue
                row_dt = _parse_timestamp(row[timestamp_idx])
                if row_dt is None:
                    continue
                if start_dt and row_dt < start_dt:
                    continue
                if end_dt and row_dt > end_dt:
                    continue
            filtered.append(row)

        self._setup_tree(self._csv_columns, filtered)
        extra = []
        if start_dt:
            extra.append(f"desde {self._results_from_var.get().strip()}")
        if end_dt:
            extra.append(f"hasta {self._results_to_var.get().strip()}")
        suffix = f" | {' | '.join(extra)}" if extra else ""
        self._status_var.set(
            f"{len(filtered):,} de {len(self._all_rows):,} filas filtradas{suffix}"
        )

    def _clear_filter(self):
        self._filter_var.set("")
        self._results_from_var.set("")
        self._results_to_var.set("")
        self._results_filters = []
        self._render_result_filter_chips()
        self._setup_tree(self._csv_columns, self._all_rows)
        self._status_var.set(f"{len(self._all_rows):,} filas (sin filtro)")

    def _on_tree_rclick(self, event):
        """Menú contextual en la tabla de Resultados."""
        region = self._tree.identify_region(event.x, event.y)
        if region not in ("cell", "heading"):
            return

        # Identificar columna y valor bajo el cursor
        col_id = self._tree.identify_column(event.x)  # "#1", "#2", ...
        row_id = self._tree.identify_row(event.y)

        try:
            col_idx = int(col_id.lstrip("#")) - 1
            col_name = (
                self._csv_columns[col_idx] if col_idx < len(self._csv_columns) else ""
            )
        except (ValueError, IndexError):
            return

        cell_value = ""
        if row_id:
            try:
                cell_value = str(self._tree.item(row_id, "values")[col_idx])
            except (IndexError, tk.TclError):
                pass

        # Construir menú dinámico
        m = self._ctx_menu
        m.delete(0, "end")

        if col_name:
            m.add_command(
                label=f'✅  Filtrar tabla: {col_name} = "{cell_value}"',
                command=lambda: self._results_filter_by(col_name, f"={cell_value}"),
            )
            m.add_command(
                label=f'❌  Excluir tabla: {col_name} ≠ "{cell_value}"',
                command=lambda: self._results_filter_by(col_name, f"!{cell_value}"),
            )
            m.add_separator()
            m.add_command(
                label=f'Análisis → Filtro 1 incluir: {col_name} = "{cell_value}"',
                command=lambda: self._send_to_analysis(
                    1, col_name, cell_value, exclude=False
                ),
            )
            m.add_command(
                label=f'Análisis → Filtro 1 excluir: {col_name} ≠ "{cell_value}"',
                command=lambda: self._send_to_analysis(
                    1, col_name, cell_value, exclude=True
                ),
            )
            m.add_command(
                label=f'Análisis → Filtro 2 incluir: {col_name} = "{cell_value}"',
                command=lambda: self._send_to_analysis(
                    2, col_name, cell_value, exclude=False
                ),
            )
            m.add_command(
                label=f'Análisis → Filtro 2 excluir: {col_name} ≠ "{cell_value}"',
                command=lambda: self._send_to_analysis(
                    2, col_name, cell_value, exclude=True
                ),
            )
            m.add_separator()
            m.add_command(
                label=f"Análisis → Agrupar por: {col_name}",
                command=lambda: self._send_to_analysis_group(col_name),
            )

        if m.index("end") is not None:
            m.tk_popup(event.x_root, event.y_root)

    def _results_filter_by(self, col_name: str, value: str):
        """Aplica filtro en la tabla de Resultados directamente."""
        self._results_filters.append({"field": col_name, "value": value})
        self._render_result_filter_chips()
        self._apply_filter()

    def _send_results_filters_to_analysis(self):
        vendor_filter = "(todos)"
        non_vendor_filters = []
        for filter_item in self._results_filters:
            field = filter_item.get("field", "")
            value = filter_item.get("value", "")
            if field == "vendor" and value.startswith("="):
                vendor_filter = value[1:].strip()
            else:
                non_vendor_filters.append(filter_item)

        self._analysis_vendor_var.set(vendor_filter)
        self._analysis_from_var.set(self._results_from_var.get().strip())
        self._analysis_to_var.set(self._results_to_var.get().strip())

        self._analysis_filter1_field_var.set(_NO_FILTER_FIELD)
        self._analysis_filter1_value_var.set("")
        self._analysis_filter2_field_var.set(_NO_FILTER_FIELD)
        self._analysis_filter2_value_var.set("")

        if non_vendor_filters:
            self._analysis_filter1_field_var.set(
                non_vendor_filters[0].get("field", _NO_FILTER_FIELD)
            )
            self._analysis_filter1_value_var.set(non_vendor_filters[0].get("value", ""))
        if len(non_vendor_filters) > 1:
            self._analysis_filter2_field_var.set(
                non_vendor_filters[1].get("field", _NO_FILTER_FIELD)
            )
            self._analysis_filter2_value_var.set(non_vendor_filters[1].get("value", ""))
        if len(non_vendor_filters) > 2:
            messagebox.showinfo(
                "Filtros trasladados",
                "Análisis solo tiene 2 filtros visibles. Se han copiado los 2 primeros más las fechas.",
            )
        self._nb.select(self._tab_analysis)

    def _send_to_analysis(
        self, slot: int, col_name: str, value: str, exclude: bool = False
    ):
        """Envía col=valor como Filtro 1 o Filtro 2 en Análisis y cambia a esa pestaña."""
        formatted = f"!{value}" if exclude else f"={value}"
        if slot == 1:
            self._analysis_filter1_field_var.set(col_name)
            self._analysis_filter1_value_var.set(formatted)
        else:
            self._analysis_filter2_field_var.set(col_name)
            self._analysis_filter2_value_var.set(formatted)
        self._nb.select(self._tab_analysis)

    def _send_to_analysis_group(self, col_name: str):
        """Pone la columna como campo de agrupación en Análisis."""
        self._pivot_col_var.set(col_name)
        self._nb.select(self._tab_analysis)

    def _sort_by(self, col: str):
        if col not in self._csv_columns:
            return
        idx = self._csv_columns.index(col)
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True

        def sort_key(row):
            val = row[idx]
            try:
                return (0, float(val))
            except (ValueError, TypeError):
                return (1, str(val).lower())

        self._all_rows.sort(key=sort_key, reverse=not self._sort_asc)
        self._apply_filter()

    # ── Pestaña Análisis ─────────────────────────────────────────────────────
    def _build_analysis_tab(self):
        tab = self._tab_analysis

        # Split horizontal: panel izquierdo (controles) + derecho (tabla+gráfico)
        paned = ttk.PanedWindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        # ── Panel izquierdo: controles ───────────────────────────────────────
        ctrl = ttk.LabelFrame(paned, text="Configuración", padding=8)
        paned.add(ctrl, weight=0)

        ttk.Label(ctrl, text="Agrupar por:").pack(anchor="w")
        self._pivot_col_var = tk.StringVar(value="src_ip")
        self._pivot_col_cb = ttk.Combobox(
            ctrl,
            textvariable=self._pivot_col_var,
            values=_PIVOT_FIELDS,
            width=22,
        )
        self._pivot_col_cb.pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Desglosar por:").pack(anchor="w")
        self._pivot_secondary_col_var = tk.StringVar(value=_NO_SECONDARY_FIELD)
        self._pivot_secondary_col_cb = ttk.Combobox(
            ctrl,
            textvariable=self._pivot_secondary_col_var,
            values=[_NO_SECONDARY_FIELD] + _PIVOT_FIELDS,
            state="readonly",
            width=22,
        )
        self._pivot_secondary_col_cb.pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Vendor: ").pack(anchor="w")
        self._analysis_vendor_var = tk.StringVar(value="(todos)")
        ttk.Combobox(
            ctrl,
            textvariable=self._analysis_vendor_var,
            values=_ANALYSIS_VENDOR_OPTIONS,
            state="readonly",
            width=22,
        ).pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Desde:").pack(anchor="w")
        analysis_from_row = ttk.Frame(ctrl)
        analysis_from_row.pack(fill="x", pady=(0, 4))
        self._analysis_from_var = tk.StringVar()
        ttk.Entry(analysis_from_row, textvariable=self._analysis_from_var).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            analysis_from_row,
            text="📅",
            width=3,
            command=lambda: self._open_calendar_popup(self._analysis_from_var),
        ).pack(side="left", padx=(4, 0))

        ttk.Label(ctrl, text="Hasta:").pack(anchor="w")
        analysis_to_row = ttk.Frame(ctrl)
        analysis_to_row.pack(fill="x", pady=(0, 8))
        self._analysis_to_var = tk.StringVar()
        ttk.Entry(analysis_to_row, textvariable=self._analysis_to_var).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            analysis_to_row,
            text="📅",
            width=3,
            command=lambda: self._open_calendar_popup(self._analysis_to_var),
        ).pack(side="left", padx=(4, 0))

        ttk.Label(ctrl, text="Filtro 1:").pack(anchor="w")
        self._analysis_filter1_field_var = tk.StringVar(value=_NO_FILTER_FIELD)
        self._analysis_filter1_field_cb = ttk.Combobox(
            ctrl,
            textvariable=self._analysis_filter1_field_var,
            values=[_NO_FILTER_FIELD] + _DERIVED_ANALYSIS_FIELDS + _PIVOT_FIELDS,
            state="readonly",
            width=22,
        )
        self._analysis_filter1_field_cb.pack(fill="x", pady=(0, 4))
        self._analysis_filter1_value_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._analysis_filter1_value_var).pack(
            fill="x", pady=(0, 8)
        )

        ttk.Label(ctrl, text="Filtro 2:").pack(anchor="w")
        self._analysis_filter2_field_var = tk.StringVar(value=_NO_FILTER_FIELD)
        self._analysis_filter2_field_cb = ttk.Combobox(
            ctrl,
            textvariable=self._analysis_filter2_field_var,
            values=[_NO_FILTER_FIELD] + _DERIVED_ANALYSIS_FIELDS + _PIVOT_FIELDS,
            state="readonly",
            width=22,
        )
        self._analysis_filter2_field_cb.pack(fill="x", pady=(0, 4))
        self._analysis_filter2_value_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._analysis_filter2_value_var).pack(
            fill="x", pady=(0, 8)
        )

        self._analysis_exclude_empty_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            ctrl,
            text="Excluir claves vacías",
            variable=self._analysis_exclude_empty_var,
        ).pack(anchor="w", pady=(0, 8))

        ttk.Label(ctrl, text="Métrica:").pack(anchor="w")
        self._pivot_metric_var = tk.StringVar(value="Recuento")
        ttk.Combobox(
            ctrl,
            textvariable=self._pivot_metric_var,
            values=_PIVOT_METRICS,
            state="readonly",
            width=22,
        ).pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Top N:").pack(anchor="w")
        topn_row = ttk.Frame(ctrl)
        topn_row.pack(fill="x", pady=(0, 8))
        self._pivot_topn_var = tk.StringVar(value="15")
        tk.Spinbox(
            topn_row,
            from_=5,
            to=200,
            increment=5,
            textvariable=self._pivot_topn_var,
            width=7,
        ).pack(side="left")
        self._pivot_topn_all = tk.BooleanVar()
        ttk.Checkbutton(topn_row, text="Todos", variable=self._pivot_topn_all).pack(
            side="left", padx=6
        )

        self._pivot_ioc_only_var = tk.BooleanVar()
        ttk.Checkbutton(
            ctrl, text="Solo IOC hits", variable=self._pivot_ioc_only_var
        ).pack(anchor="w", pady=(0, 8))

        ttk.Label(ctrl, text="Tipo de gráfico:").pack(anchor="w")
        self._pivot_chart_var = tk.StringVar(value="Barras horizontales")
        ttk.Combobox(
            ctrl,
            textvariable=self._pivot_chart_var,
            values=_CHART_TYPES,
            state="readonly",
            width=22,
        ).pack(fill="x", pady=(0, 10))

        ttk.Button(ctrl, text="▶  Generar", command=self._generate_pivot).pack(fill="x")
        ttk.Button(ctrl, text="💾  Exportar imagen…", command=self._export_chart).pack(
            fill="x", pady=(4, 0)
        )
        ttk.Separator(ctrl, orient="horizontal").pack(fill="x", pady=8)

        ttk.Label(ctrl, text="Anomalías temporales:", font=("", 9, "bold")).pack(
            anchor="w", pady=(0, 4)
        )
        ttk.Label(ctrl, text="Intervalo:").pack(anchor="w")
        self._anomaly_bucket_var = tk.StringVar(value="Hora")
        ttk.Combobox(
            ctrl,
            textvariable=self._anomaly_bucket_var,
            values=_ANOMALY_BUCKETS,
            state="readonly",
            width=22,
        ).pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Métrica temporal:").pack(anchor="w")
        self._anomaly_metric_var = tk.StringVar(value="Recuento")
        ttk.Combobox(
            ctrl,
            textvariable=self._anomaly_metric_var,
            values=_ANOMALY_METRICS,
            state="readonly",
            width=22,
        ).pack(fill="x", pady=(0, 8))

        ttk.Button(ctrl, text="▲  Detectar picos", command=self._detect_anomalies).pack(
            fill="x"
        )
        ttk.Button(
            ctrl,
            text="Picos IOC por hora",
            command=lambda: self._detect_anomalies(bucket="Hora", ioc_only=True),
        ).pack(fill="x", pady=(4, 0))
        ttk.Button(
            ctrl,
            text="📅  Histograma temporal",
            command=self._draw_time_histogram,
        ).pack(fill="x", pady=(4, 8))

        ttk.Separator(ctrl, orient="horizontal").pack(fill="x", pady=8)

        # Accesos rápidos
        ttk.Label(ctrl, text="Accesos rápidos:", font=("", 9, "bold")).pack(
            anchor="w", pady=(0, 4)
        )
        ttk.Label(
            ctrl,
            text="(filtros: = exacto, ! excluye)",
            font=("", 7),
            foreground="#888888",
        ).pack(anchor="w", pady=(0, 4))
        presets = [
            # ── Generales ───────────────────────────────────────
            dict(
                label="Top IPs origen",
                col="src_ip",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="Acciones fw",
                col="action",
                metric="Recuento",
                chart="Quesito (pie)",
            ),
            dict(
                label="Aplicaciones",
                col="app",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="Puertos destino",
                col="dest_port",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="Zona origen",
                col="src_zone",
                metric="Recuento",
                chart="Quesito (pie)",
            ),
            dict(
                label="Protocolo",
                col="transport",
                metric="Recuento",
                chart="Quesito (pie)",
            ),
            dict(
                label="Vendor / fuente",
                col="vendor",
                metric="Recuento",
                chart="Barras verticales",
            ),
            dict(
                label="Reglas firewall",
                col="rule",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="Volumen por IP src",
                col="src_ip",
                metric="Suma bytes_total",
                chart="Barras horizontales",
            ),
            # ── IOC ────────────────────────────────────────────────────
            dict(
                label="País destino (IOC)",
                col="ioc_dst_country",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="País origen (IOC)",
                col="ioc_src_country",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="Riesgo IOC dst",
                col="ioc_dst_risk",
                metric="Recuento",
                chart="Barras verticales",
            ),
            dict(
                label="Top IOC hits",
                col="ioc_dst_source",
                metric="Recuento",
                chart="Barras horizontales",
                ioc_only=True,
            ),
            # ── Granulares ──────────────────────────────────────────────
            dict(
                label="Top IPs → allow",
                col="src_ip",
                metric="Recuento",
                chart="Barras horizontales",
                f1_field="action",
                f1_value="=allow",
            ),
            dict(
                label="Top IPs → deny/drop",
                col="src_ip",
                metric="Recuento",
                chart="Barras horizontales",
                f1_field="action",
                f1_value="deny",
            ),
            dict(
                label="Top IPs src (no WiFi)",
                col="src_ip",
                metric="Recuento",
                chart="Barras horizontales",
                f1_field="src_zone",
                f1_value="!wifi",
            ),
            dict(
                label="Top IPs src / acción",
                col="src_ip",
                secondary="action",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="Top IPs src / país dst",
                col="src_ip",
                secondary="ioc_dst_country",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="App / zona origen",
                col="app",
                secondary="src_zone",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="Regla / acción",
                col="rule",
                secondary="action",
                metric="Recuento",
                chart="Barras horizontales",
            ),
            dict(
                label="Destino externo allow",
                col="dest_ip",
                metric="Recuento",
                chart="Barras horizontales",
                f1_field="action",
                f1_value="=allow",
                f2_field="traffic_scope",
                f2_value="=lan→wan",
            ),
            dict(
                label="Src no WiFi allow",
                col="src_ip",
                secondary="app",
                metric="Recuento",
                chart="Barras horizontales",
                f1_field="action",
                f1_value="=allow",
                f2_field="src_zone",
                f2_value="!wifi",
            ),
        ]
        for p in presets:
            ttk.Button(
                ctrl,
                text=p["label"],
                command=lambda kw=p: self._apply_preset(
                    kw["col"],
                    kw["metric"],
                    kw["chart"],
                    secondary=kw.get("secondary"),
                    f1_field=kw.get("f1_field"),
                    f1_value=kw.get("f1_value", ""),
                    f2_field=kw.get("f2_field"),
                    f2_value=kw.get("f2_value", ""),
                    ioc_only=kw.get("ioc_only"),
                ),
            ).pack(fill="x", pady=1)

        # ── Panel derecho: tabla + gráfico ───────────────────────────────────
        right = ttk.PanedWindow(paned, orient="vertical")
        paned.add(right, weight=1)

        # Tabla pivot
        tbl_frame = ttk.LabelFrame(right, text="Tabla pivot", padding=4)
        right.add(tbl_frame, weight=1)
        self._pivot_tree = ttk.Treeview(tbl_frame, show="headings", height=8)
        vsb_p = ttk.Scrollbar(
            tbl_frame, orient="vertical", command=self._pivot_tree.yview
        )
        self._pivot_tree.configure(yscrollcommand=vsb_p.set)
        self._pivot_tree.pack(side="left", fill="both", expand=True)
        vsb_p.pack(side="right", fill="y")

        # Área de gráfico
        chart_frame = ttk.LabelFrame(right, text="Gráfico", padding=4)
        right.add(chart_frame, weight=2)

        if _HAS_MPL:
            self._fig = Figure(figsize=(8.8, 5.2), dpi=110, facecolor="#ffffff")
            self._canvas_mpl = FigureCanvasTkAgg(self._fig, master=chart_frame)
            self._canvas_mpl.get_tk_widget().pack(fill="both", expand=True)
        else:
            self._canvas_mpl = None
            ttk.Label(
                chart_frame,
                text="matplotlib no disponible.\nInstala con:  pip install matplotlib",
                justify="center",
                foreground="gray",
            ).pack(expand=True)

    def _build_histograms_tab(self):
        tab = self._tab_histograms

        paned = ttk.PanedWindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        ctrl = ttk.LabelFrame(paned, text="Configuración temporal", padding=8)
        paned.add(ctrl, weight=0)

        ttk.Label(ctrl, text="Serie por:").pack(anchor="w")
        self._hist_series_col_var = tk.StringVar(value=_NO_SERIES_FIELD)
        self._hist_series_col_cb = ttk.Combobox(
            ctrl,
            textvariable=self._hist_series_col_var,
            values=[_NO_SERIES_FIELD] + _PIVOT_FIELDS,
            state="readonly",
            width=22,
        )
        self._hist_series_col_cb.pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Vendor:").pack(anchor="w")
        self._hist_vendor_var = tk.StringVar(value="(todos)")
        ttk.Combobox(
            ctrl,
            textvariable=self._hist_vendor_var,
            values=_ANALYSIS_VENDOR_OPTIONS,
            state="readonly",
            width=22,
        ).pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Desde:").pack(anchor="w")
        self._hist_from_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._hist_from_var).pack(fill="x", pady=(0, 4))
        ttk.Label(ctrl, text="Hasta:").pack(anchor="w")
        self._hist_to_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._hist_to_var).pack(fill="x", pady=(0, 8))
        ttk.Label(
            ctrl, text="Formato: YYYY-MM-DD o YYYY-MM-DD HH:MM", foreground="#777777"
        ).pack(anchor="w", pady=(0, 8))

        ttk.Label(ctrl, text="Filtro 1:").pack(anchor="w")
        self._hist_filter1_field_var = tk.StringVar(value=_NO_FILTER_FIELD)
        self._hist_filter1_field_cb = ttk.Combobox(
            ctrl,
            textvariable=self._hist_filter1_field_var,
            values=[_NO_FILTER_FIELD] + _DERIVED_ANALYSIS_FIELDS + _PIVOT_FIELDS,
            state="readonly",
            width=22,
        )
        self._hist_filter1_field_cb.pack(fill="x", pady=(0, 4))
        self._hist_filter1_value_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._hist_filter1_value_var).pack(
            fill="x", pady=(0, 8)
        )

        ttk.Label(ctrl, text="Filtro 2:").pack(anchor="w")
        self._hist_filter2_field_var = tk.StringVar(value=_NO_FILTER_FIELD)
        self._hist_filter2_field_cb = ttk.Combobox(
            ctrl,
            textvariable=self._hist_filter2_field_var,
            values=[_NO_FILTER_FIELD] + _DERIVED_ANALYSIS_FIELDS + _PIVOT_FIELDS,
            state="readonly",
            width=22,
        )
        self._hist_filter2_field_cb.pack(fill="x", pady=(0, 4))
        self._hist_filter2_value_var = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self._hist_filter2_value_var).pack(
            fill="x", pady=(0, 8)
        )

        ttk.Label(ctrl, text="Intervalo:").pack(anchor="w")
        self._hist_bucket_var = tk.StringVar(value="Hora")
        ttk.Combobox(
            ctrl,
            textvariable=self._hist_bucket_var,
            values=_ANOMALY_BUCKETS,
            state="readonly",
            width=22,
        ).pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Métrica:").pack(anchor="w")
        self._hist_metric_var = tk.StringVar(value="Recuento")
        ttk.Combobox(
            ctrl,
            textvariable=self._hist_metric_var,
            values=_ANOMALY_METRICS,
            state="readonly",
            width=22,
        ).pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Top series:").pack(anchor="w")
        hist_top_row = ttk.Frame(ctrl)
        hist_top_row.pack(fill="x", pady=(0, 8))
        self._hist_topn_var = tk.StringVar(value="8")
        tk.Spinbox(
            hist_top_row,
            from_=1,
            to=30,
            increment=1,
            textvariable=self._hist_topn_var,
            width=7,
        ).pack(side="left")
        self._hist_topn_all = tk.BooleanVar()
        ttk.Checkbutton(hist_top_row, text="Todas", variable=self._hist_topn_all).pack(
            side="left", padx=6
        )

        self._hist_exclude_empty_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            ctrl, text="Excluir claves vacías", variable=self._hist_exclude_empty_var
        ).pack(anchor="w", pady=(0, 6))
        self._hist_ioc_only_var = tk.BooleanVar()
        ttk.Checkbutton(
            ctrl, text="Solo IOC hits", variable=self._hist_ioc_only_var
        ).pack(anchor="w", pady=(0, 8))

        ttk.Button(
            ctrl, text="📊  Generar histograma", command=self._generate_histogram_view
        ).pack(fill="x")
        ttk.Button(
            ctrl, text="💾  Exportar imagen…", command=self._export_hist_chart
        ).pack(fill="x", pady=(4, 0))

        ttk.Separator(ctrl, orient="horizontal").pack(fill="x", pady=8)
        ttk.Label(ctrl, text="Ejemplos:", font=("", 9, "bold")).pack(
            anchor="w", pady=(0, 4)
        )
        ttk.Label(
            ctrl,
            text="Serie por src_zone\nSerie por dest_country\nSerie por src_ip",
            foreground="#666666",
            justify="left",
        ).pack(anchor="w")

        right = ttk.PanedWindow(paned, orient="vertical")
        paned.add(right, weight=1)

        tbl_frame = ttk.LabelFrame(right, text="Series", padding=4)
        right.add(tbl_frame, weight=1)
        self._hist_tree = ttk.Treeview(tbl_frame, show="headings", height=8)
        hist_vsb = ttk.Scrollbar(
            tbl_frame, orient="vertical", command=self._hist_tree.yview
        )
        self._hist_tree.configure(yscrollcommand=hist_vsb.set)
        self._hist_tree.pack(side="left", fill="both", expand=True)
        hist_vsb.pack(side="right", fill="y")

        chart_frame = ttk.LabelFrame(right, text="Histograma", padding=4)
        right.add(chart_frame, weight=2)
        if _HAS_MPL:
            self._hist_fig = Figure(figsize=(8.8, 5.2), dpi=110, facecolor="#ffffff")
            self._hist_canvas_mpl = FigureCanvasTkAgg(
                self._hist_fig, master=chart_frame
            )
            self._hist_canvas_mpl.get_tk_widget().pack(fill="both", expand=True)
        else:
            self._hist_canvas_mpl = None
            ttk.Label(
                chart_frame,
                text="matplotlib no disponible.\nInstala con:  pip install matplotlib",
                justify="center",
                foreground="gray",
            ).pack(expand=True)

        self._hist_status_var = tk.StringVar(
            value="Carga un CSV para generar histogramas."
        )
        ttk.Label(tab, textvariable=self._hist_status_var, anchor="w").pack(
            fill="x", padx=8, pady=(0, 4)
        )

    def _apply_preset(
        self,
        col: str,
        metric: str,
        chart: str,
        secondary: str | None = None,
        f1_field: str | None = None,
        f1_value: str = "",
        f2_field: str | None = None,
        f2_value: str = "",
        ioc_only: bool | None = None,
    ):
        self._pivot_col_var.set(col)
        self._pivot_secondary_col_var.set(secondary or _NO_SECONDARY_FIELD)
        self._pivot_metric_var.set(metric)
        self._pivot_chart_var.set(chart)
        self._analysis_filter1_field_var.set(f1_field or _NO_FILTER_FIELD)
        self._analysis_filter1_value_var.set(f1_value)
        self._analysis_filter2_field_var.set(f2_field or _NO_FILTER_FIELD)
        self._analysis_filter2_value_var.set(f2_value)
        if ioc_only is not None:
            self._pivot_ioc_only_var.set(ioc_only)
        self._generate_pivot()

    def _get_row_value(self, row: list, field_name: str) -> str:
        if field_name in self._csv_columns:
            return str(row[self._csv_columns.index(field_name)] or "").strip()

        src_ip = (
            self._get_row_value(row, "src_ip") if "src_ip" in self._csv_columns else ""
        )
        dest_ip = (
            self._get_row_value(row, "dest_ip")
            if "dest_ip" in self._csv_columns
            else ""
        )
        if field_name == "traffic_scope":
            src_private = _is_private_ip(src_ip)
            dest_private = _is_private_ip(dest_ip)
            if src_private and dest_private:
                return "interno-interno"
            if src_private and not dest_private:
                return "interno-externo"
            if not src_private and dest_private:
                return "externo-interno"
            return "externo-externo"

        if field_name == "ioc_scope":
            src_ioc = (
                self._get_row_value(row, "ioc_src") == "YES"
                if "ioc_src" in self._csv_columns
                else False
            )
            dst_ioc = (
                self._get_row_value(row, "ioc_dst") == "YES"
                if "ioc_dst" in self._csv_columns
                else False
            )
            if src_ioc and dst_ioc:
                return "src+dst"
            if src_ioc:
                return "src"
            if dst_ioc:
                return "dst"
            return "none"

        if field_name == "dest_port_band":
            return _port_band(self._get_row_value(row, "dest_port"))

        if field_name == "src_port_band":
            return _port_band(self._get_row_value(row, "src_port"))

        return ""

    def _field_exists_for_analysis(self, field_name: str) -> bool:
        return field_name in self._csv_columns or field_name in _DERIVED_ANALYSIS_FIELDS

    def _apply_generic_filter(
        self, row: list, field_name: str, filter_value: str
    ) -> bool:
        if not field_name or field_name == _NO_FILTER_FIELD or not filter_value:
            return True
        raw_value = str(filter_value or "").strip()
        exact = raw_value.startswith("=")
        exclude = raw_value.startswith("!")
        cmp_value = raw_value[1:].strip() if (exact or exclude) else raw_value
        cell_value = self._get_row_value(row, field_name).lower()
        if exact:
            return cell_value == cmp_value.lower()
        if exclude:
            return cmp_value.lower() not in cell_value
        return cmp_value.lower() in cell_value

    def _parse_time_bound(
        self, raw_value: str, is_end: bool = False
    ) -> datetime | None:
        text = str(raw_value or "").strip()
        if not text:
            return None
        parsed = _parse_timestamp(text)
        if parsed is None:
            return None
        if ":" not in text and len(text) <= 10:
            if is_end:
                return parsed.replace(hour=23, minute=59, second=59, microsecond=999999)
            return parsed.replace(hour=0, minute=0, second=0, microsecond=0)
        return parsed

    def _get_rows_with_filters(
        self,
        rows: list,
        vendor_filter: str,
        filter1_field: str,
        filter1_value: str,
        filter2_field: str,
        filter2_value: str,
        ioc_only: bool = False,
        from_value: str = "",
        to_value: str = "",
    ) -> list:
        start_dt = self._parse_time_bound(from_value, is_end=False)
        end_dt = self._parse_time_bound(to_value, is_end=True)
        timestamp_idx = (
            self._csv_columns.index("timestamp")
            if "timestamp" in self._csv_columns
            else -1
        )

        result = []
        for row in rows:
            if vendor_filter and vendor_filter != "(todos)":
                if self._get_row_value(row, "vendor") != vendor_filter:
                    continue
            if ioc_only:
                src_ioc = (
                    self._get_row_value(row, "ioc_src") == "YES"
                    if "ioc_src" in self._csv_columns
                    else False
                )
                dst_ioc = (
                    self._get_row_value(row, "ioc_dst") == "YES"
                    if "ioc_dst" in self._csv_columns
                    else False
                )
                if not (src_ioc or dst_ioc):
                    continue
            if not self._apply_generic_filter(row, filter1_field, filter1_value):
                continue
            if not self._apply_generic_filter(row, filter2_field, filter2_value):
                continue
            if start_dt or end_dt:
                if timestamp_idx < 0:
                    continue
                row_dt = _parse_timestamp(row[timestamp_idx])
                if row_dt is None:
                    continue
                if start_dt and row_dt < start_dt:
                    continue
                if end_dt and row_dt > end_dt:
                    continue
            result.append(row)
        return result

    def _build_filter_subtitle(
        self,
        vendor_filter: str,
        filter1_field: str,
        filter1_value: str,
        filter2_field: str,
        filter2_value: str,
        ioc_only: bool = False,
        from_value: str = "",
        to_value: str = "",
    ) -> str:
        parts = []
        if vendor_filter and vendor_filter != "(todos)":
            parts.append(f"vendor={vendor_filter}")
        for field_name, field_value in (
            (filter1_field, filter1_value),
            (filter2_field, filter2_value),
        ):
            if field_name and field_name != _NO_FILTER_FIELD and field_value:
                if field_value.startswith("!"):
                    op = "≠"
                    value = field_value[1:].strip()
                elif field_value.startswith("="):
                    op = "="
                    value = field_value[1:].strip()
                else:
                    op = "≈"
                    value = field_value.strip()
                parts.append(f"{field_name}{op}{value}")
        if from_value:
            parts.append(f"desde={from_value}")
        if to_value:
            parts.append(f"hasta={to_value}")
        if ioc_only:
            parts.append("solo IOC")
        return "  |  ".join(parts)

    def _get_analysis_rows(self, rows: list) -> list:
        return self._get_rows_with_filters(
            rows,
            vendor_filter=self._analysis_vendor_var.get().strip(),
            filter1_field=self._analysis_filter1_field_var.get().strip(),
            filter1_value=self._analysis_filter1_value_var.get().strip(),
            filter2_field=self._analysis_filter2_field_var.get().strip(),
            filter2_value=self._analysis_filter2_value_var.get().strip(),
            ioc_only=self._pivot_ioc_only_var.get(),
            from_value=self._analysis_from_var.get().strip(),
            to_value=self._analysis_to_var.get().strip(),
        )

    def _get_ioc_filtered_rows(self, rows: list) -> list:
        if not self._pivot_ioc_only_var.get():
            return rows

        idx_s = (
            self._csv_columns.index("ioc_src") if "ioc_src" in self._csv_columns else -1
        )
        idx_d = (
            self._csv_columns.index("ioc_dst") if "ioc_dst" in self._csv_columns else -1
        )
        return [
            row
            for row in rows
            if (idx_s >= 0 and row[idx_s] == "YES")
            or (idx_d >= 0 and row[idx_d] == "YES")
        ]

    def _generate_pivot(self):
        if not self._all_rows or not self._csv_columns:
            messagebox.showwarning(
                "Sin datos",
                "Carga primero un CSV en la pestaña Resultados o desde allí.",
            )
            return

        col = self._pivot_col_var.get().strip()
        if not self._field_exists_for_analysis(col):
            messagebox.showerror(
                "Error", f"Columna '{col}' no encontrada en los datos."
            )
            return

        secondary_col = self._pivot_secondary_col_var.get().strip()
        use_secondary = secondary_col and secondary_col != _NO_SECONDARY_FIELD
        if use_secondary and not self._field_exists_for_analysis(secondary_col):
            messagebox.showerror(
                "Error", f"Columna secundaria '{secondary_col}' no encontrada."
            )
            return

        metric = self._pivot_metric_var.get()
        secondary_idx = secondary_col if use_secondary else None

        # Columna de métrica numérica
        metric_col_idx = None
        metric_label = "Recuento"
        if metric != "Recuento":
            metric_col_name = metric.replace("Suma ", "")
            if metric_col_name in self._csv_columns:
                metric_col_idx = self._csv_columns.index(metric_col_name)
                metric_label = metric

        # Filtro IOC only
        rows = self._get_analysis_rows(self._all_rows)

        # Subtítulo con filtros activos
        _fparts: list[str] = []
        _vnd = self._analysis_vendor_var.get().strip()
        if _vnd and _vnd != "(todos)":
            _fparts.append(f"vendor={_vnd}")
        for _ff, _fv in (
            (
                self._analysis_filter1_field_var.get().strip(),
                self._analysis_filter1_value_var.get().strip(),
            ),
            (
                self._analysis_filter2_field_var.get().strip(),
                self._analysis_filter2_value_var.get().strip(),
            ),
        ):
            if _ff and _ff != _NO_FILTER_FIELD and _fv:
                _op = (
                    "≠"
                    if _fv.startswith("!")
                    else ("=" if _fv.startswith("=") else "≈")
                )
                _fparts.append(f"{_ff}{_op}{_fv.lstrip('!=').strip()}")
        if self._pivot_ioc_only_var.get():
            _fparts.append("solo IOC")
        _subtitle = "  |  ".join(_fparts)

        # Agrupación
        agg: dict = defaultdict(float)
        for row in rows:
            primary_value = self._get_row_value(row, col) or "(vacío)"
            if self._analysis_exclude_empty_var.get() and primary_value == "(vacío)":
                continue
            if secondary_idx is not None:
                secondary_value = self._get_row_value(row, secondary_idx) or "(vacío)"
                if (
                    self._analysis_exclude_empty_var.get()
                    and secondary_value == "(vacío)"
                ):
                    continue
                key = (primary_value, secondary_value)
            else:
                key = primary_value
            if metric_col_idx is not None:
                try:
                    agg[key] += float(row[metric_col_idx])
                except (ValueError, TypeError):
                    pass
            else:
                agg[key] += 1

        sorted_items = sorted(agg.items(), key=lambda x: x[1], reverse=True)
        if not self._pivot_topn_all.get():
            try:
                n = int(self._pivot_topn_var.get())
            except ValueError:
                n = 15
            sorted_items = sorted_items[:n]

        labels = [it[0] for it in sorted_items]
        values = [it[1] for it in sorted_items]
        total = sum(values) or 1

        # ── Actualizar tabla pivot ────────────────────────────────────────────
        tree = self._pivot_tree
        tree.delete(*tree.get_children())
        if secondary_idx is not None:
            tree["columns"] = (col, secondary_col, metric_label, "% total")
            tree.heading(col, text=col)
            tree.heading(secondary_col, text=secondary_col)
            tree.heading(metric_label, text=metric_label)
            tree.heading("% total", text="% total")
            tree.column(col, width=160, minwidth=80)
            tree.column(secondary_col, width=160, minwidth=80)
            tree.column(metric_label, width=110, minwidth=60)
            tree.column("% total", width=80, minwidth=50)
        else:
            tree["columns"] = (col, metric_label, "% total")
            tree.heading(col, text=col)
            tree.heading(metric_label, text=metric_label)
            tree.heading("% total", text="% total")
            tree.column(col, width=200, minwidth=80)
            tree.column(metric_label, width=110, minwidth=60)
            tree.column("% total", width=80, minwidth=50)

        chart_labels = []
        for lbl, val in zip(labels, values):
            disp = f"{val:,.0f}" if val == int(val) else f"{val:,.1f}"
            if secondary_idx is not None:
                primary_value, secondary_value = lbl
                tree.insert(
                    "",
                    "end",
                    values=(
                        primary_value,
                        secondary_value,
                        disp,
                        f"{val / total * 100:.1f}%",
                    ),
                )
                chart_labels.append(f"{primary_value} / {secondary_value}")
            else:
                tree.insert("", "end", values=(lbl, disp, f"{val / total * 100:.1f}%"))
                chart_labels.append(lbl)

        # ── Dibujar gráfico ───────────────────────────────────────────────────
        if self._canvas_mpl is not None:
            chart_title = col if secondary_idx is None else f"{col} / {secondary_col}"
            self._draw_chart(
                chart_labels,
                values,
                chart_title,
                metric_label,
                self._pivot_chart_var.get(),
                subtitle=_subtitle,
            )

        self._nb.select(self._tab_analysis)

    def _detect_anomalies(self, bucket: str | None = None, ioc_only: bool = False):
        if not self._all_rows or not self._csv_columns:
            messagebox.showwarning("Sin datos", "Carga primero un CSV para analizarlo.")
            return
        if "timestamp" not in self._csv_columns:
            messagebox.showerror(
                "Sin timestamp", "El CSV no contiene la columna 'timestamp'."
            )
            return

        bucket = bucket or self._anomaly_bucket_var.get()
        metric = self._anomaly_metric_var.get()
        timestamp_idx = self._csv_columns.index("timestamp")
        metric_idx = None
        if metric != "Recuento":
            metric_name = metric.replace("Suma ", "")
            if metric_name not in self._csv_columns:
                messagebox.showerror(
                    "Métrica no disponible", f"No existe la columna '{metric_name}'."
                )
                return
            metric_idx = self._csv_columns.index(metric_name)

        previous_ioc_only = self._pivot_ioc_only_var.get()
        if ioc_only:
            self._pivot_ioc_only_var.set(True)
        rows = self._get_analysis_rows(self._all_rows)
        if ioc_only:
            self._pivot_ioc_only_var.set(previous_ioc_only)

        grouped: dict = defaultdict(float)
        parsed_rows = 0
        for row in rows:
            dt = _parse_timestamp(row[timestamp_idx])
            if dt is None:
                continue
            bucket_dt = _floor_timestamp(dt, bucket)
            if metric_idx is None:
                grouped[bucket_dt] += 1
            else:
                grouped[bucket_dt] += _safe_float(row[metric_idx])
            parsed_rows += 1

        if not grouped:
            messagebox.showwarning(
                "Sin serie temporal",
                "No se han podido interpretar timestamps válidos en los datos cargados.",
            )
            return

        series = sorted(grouped.items(), key=lambda item: item[0])
        mean_value, std_value, threshold, peaks = _detect_spikes(series)

        tree = self._pivot_tree
        tree.delete(*tree.get_children())
        tree["columns"] = (
            "intervalo",
            "valor",
            "media",
            "umbral",
            "zscore",
            "severidad",
        )
        for name, width in (
            ("intervalo", 150),
            ("valor", 90),
            ("media", 90),
            ("umbral", 90),
            ("zscore", 70),
            ("severidad", 80),
        ):
            tree.heading(name, text=name.title())
            tree.column(name, width=width, minwidth=60)

        for peak in peaks:
            tree.insert(
                "",
                "end",
                values=(
                    _format_bucket(peak["bucket_dt"], bucket),
                    f"{peak['value']:,.0f}",
                    f"{mean_value:,.1f}",
                    f"{threshold:,.1f}",
                    f"{peak['z_score']:.2f}",
                    peak["severity"],
                ),
            )

        labels = [_format_bucket(bucket_dt, bucket) for bucket_dt, _ in series]
        values = [value for _, value in series]
        if self._canvas_mpl is not None:
            self._draw_time_series(
                labels, values, series, mean_value, threshold, peaks, bucket, metric
            )

        peak_count = len(peaks)
        scope = " | solo IOC" if ioc_only or previous_ioc_only else ""
        self._status_var.set(
            f"Serie temporal: {parsed_rows:,} filas válidas | {peak_count} picos detectados | {bucket}{scope}"
        )
        self._nb.select(self._tab_analysis)

    def _style_axis(self, ax, value_axis: str = "x"):
        ax.set_facecolor("#fbfbfb")
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        ax.spines["left"].set_color("#d0d0d0")
        ax.spines["bottom"].set_color("#d0d0d0")
        if value_axis == "x":
            ax.grid(axis="x", color="#e8e8e8", linestyle="--", linewidth=0.8)
        elif value_axis == "y":
            ax.grid(axis="y", color="#e8e8e8", linestyle="--", linewidth=0.8)
        ax.tick_params(colors="#444444")

    def _draw_chart(
        self,
        labels: list,
        values: list,
        col: str,
        metric: str,
        chart_type: str,
        subtitle: str = "",
    ):
        self._fig.clear()
        ax = self._fig.add_subplot(111)
        n = len(labels)
        pretty_labels = [_truncate_label(label, 34) for label in labels]
        colors = (_CHART_COLORS * ((n // len(_CHART_COLORS)) + 1))[:n]
        total = sum(values) or 1

        if chart_type == "Barras horizontales":
            y_pos = list(range(n))
            ax.barh(y_pos, values, color=colors)
            self._style_axis(ax, value_axis="x")
            ax.set_yticks(y_pos)
            ax.set_yticklabels(pretty_labels, fontsize=8)
            ax.invert_yaxis()
            ax.set_xlabel(metric, fontsize=9)
            for i, v in enumerate(values):
                ax.text(
                    v,
                    i,
                    f"  {v:,.0f} ({v / total * 100:.1f}%)",
                    va="center",
                    fontsize=7,
                    color="#333333",
                )

        elif chart_type == "Barras verticales":
            x_pos = list(range(n))
            ax.bar(x_pos, values, color=colors)
            self._style_axis(ax, value_axis="y")
            ax.set_xticks(x_pos)
            ax.set_xticklabels(pretty_labels, rotation=38, ha="right", fontsize=8)
            ax.set_ylabel(metric, fontsize=9)
            for i, v in enumerate(values):
                ax.text(
                    i,
                    v,
                    f"{v:,.0f}",
                    ha="center",
                    va="bottom",
                    fontsize=7,
                    color="#333333",
                )

        elif chart_type == "Quesito (pie)":
            wedge = {"edgecolor": "white", "linewidth": 1.2}
            ax.pie(
                values,
                labels=pretty_labels,
                autopct="%1.1f%%",
                colors=colors,
                wedgeprops=wedge,
                textprops={"fontsize": 8},
            )

        elif chart_type == "Donut":
            wedge = {"width": 0.42, "edgecolor": "white", "linewidth": 1.2}
            ax.pie(
                values,
                labels=pretty_labels,
                autopct="%1.1f%%",
                colors=colors,
                wedgeprops=wedge,
                textprops={"fontsize": 8},
                pctdistance=0.8,
                labeldistance=1.06,
            )
            ax.text(
                0,
                0,
                f"{len(values)}\nseries",
                ha="center",
                va="center",
                fontsize=10,
                color="#333333",
            )

        elif chart_type == "Línea":
            x_pos = list(range(n))
            ax.plot(x_pos, values, marker="o", color=colors[0], linewidth=2)
            ax.fill_between(x_pos, values, alpha=0.15, color=colors[0])
            self._style_axis(ax, value_axis="y")
            ax.set_xticks(x_pos)
            step = max(1, len(pretty_labels) // 12)
            ax.set_xticks(x_pos[::step])
            ax.set_xticklabels(
                pretty_labels[::step], rotation=38, ha="right", fontsize=8
            )
            ax.set_ylabel(metric, fontsize=9)

        if subtitle:
            ax.set_title(
                f"{col}  —  {metric}\n{subtitle}",
                fontsize=10,
                pad=8,
                color="#222222",
            )
        else:
            ax.set_title(f"{col}  —  {metric}", fontsize=11, pad=10, color="#222222")
        self._fig.tight_layout()
        self._canvas_mpl.draw()

    def _draw_time_series(
        self,
        labels: list,
        values: list,
        series: list[tuple[datetime, float]],
        mean_value: float,
        threshold: float,
        peaks: list[dict],
        bucket: str,
        metric: str,
    ):
        self._fig.clear()
        ax = self._fig.add_subplot(111)
        x_pos = list(range(len(labels)))
        pretty_labels = [_truncate_label(label, 22) for label in labels]
        ax.plot(x_pos, values, marker="o", color="#377eb8", linewidth=2, label="Serie")
        ax.fill_between(x_pos, values, alpha=0.12, color="#377eb8")
        ax.axhline(
            mean_value, color="#666666", linestyle="--", linewidth=1.2, label="Media"
        )
        ax.axhline(
            threshold,
            color="#e41a1c",
            linestyle=":",
            linewidth=1.4,
            label="Umbral pico",
        )
        self._style_axis(ax, value_axis="y")

        peak_lookup = {peak["bucket_dt"]: peak["value"] for peak in peaks}
        peak_x = []
        peak_y = []
        for idx, (bucket_dt, value) in enumerate(series):
            if bucket_dt in peak_lookup:
                peak_x.append(idx)
                peak_y.append(value)
        if peak_x:
            ax.scatter(peak_x, peak_y, color="#e41a1c", s=48, zorder=3, label="Picos")

        step = max(1, len(labels) // 12)
        ax.set_xticks(x_pos[::step])
        ax.set_xticklabels(pretty_labels[::step], rotation=38, ha="right", fontsize=8)
        ax.set_ylabel(metric, fontsize=9)
        ax.set_title(
            f"Picos temporales por {bucket.lower()} — {metric}",
            fontsize=11,
            pad=10,
            color="#222222",
        )
        ax.legend(fontsize=8)
        self._fig.tight_layout()
        self._canvas_mpl.draw()

    def _draw_time_histogram(self):
        """Histograma de barras por fecha/hora (estilo QRadar), sin detección de picos."""
        if not self._all_rows or not self._csv_columns:
            messagebox.showwarning("Sin datos", "Carga primero un CSV para analizarlo.")
            return
        if "timestamp" not in self._csv_columns:
            messagebox.showerror(
                "Sin timestamp", "El CSV no contiene la columna 'timestamp'."
            )
            return

        bucket = self._anomaly_bucket_var.get()
        metric = self._anomaly_metric_var.get()
        timestamp_idx = self._csv_columns.index("timestamp")
        metric_idx = None
        if metric != "Recuento":
            metric_name = metric.replace("Suma ", "")
            if metric_name not in self._csv_columns:
                messagebox.showerror(
                    "Métrica no disponible", f"No existe la columna '{metric_name}'."
                )
                return
            metric_idx = self._csv_columns.index(metric_name)

        rows = self._get_analysis_rows(self._all_rows)
        grouped: dict = defaultdict(float)
        parsed_rows = 0
        for row in rows:
            dt = _parse_timestamp(row[timestamp_idx])
            if dt is None:
                continue
            bucket_dt = _floor_timestamp(dt, bucket)
            grouped[bucket_dt] += (
                1 if metric_idx is None else _safe_float(row[metric_idx])
            )
            parsed_rows += 1

        if not grouped:
            messagebox.showwarning(
                "Sin serie temporal",
                "No se han podido interpretar timestamps válidos en los datos cargados.",
            )
            return

        series = sorted(grouped.items())
        labels = [_format_bucket(bk, bucket) for bk, _ in series]
        values = [v for _, v in series]
        n = len(labels)
        step = max(1, n // 20)

        if self._canvas_mpl is None:
            return
        self._fig.clear()
        ax = self._fig.add_subplot(111)
        x_pos = list(range(n))
        ax.bar(x_pos, values, color="#377eb8", width=0.85, linewidth=0)
        self._style_axis(ax, value_axis="y")
        ax.set_xticks(x_pos[::step])
        ax.set_xticklabels(labels[::step], rotation=38, ha="right", fontsize=8)
        ax.set_ylabel(metric, fontsize=9)

        # Subtítulo con filtros activos
        _fparts: list[str] = []
        _vnd = self._analysis_vendor_var.get().strip()
        if _vnd and _vnd != "(todos)":
            _fparts.append(f"vendor={_vnd}")
        for _ff, _fv in (
            (
                self._analysis_filter1_field_var.get().strip(),
                self._analysis_filter1_value_var.get().strip(),
            ),
            (
                self._analysis_filter2_field_var.get().strip(),
                self._analysis_filter2_value_var.get().strip(),
            ),
        ):
            if _ff and _ff != _NO_FILTER_FIELD and _fv:
                _op = (
                    "≠"
                    if _fv.startswith("!")
                    else ("=" if _fv.startswith("=") else "≈")
                )
                _fparts.append(f"{_ff}{_op}{_fv.lstrip('!=').strip()}")
        if self._pivot_ioc_only_var.get():
            _fparts.append("solo IOC")
        _subtitle = "  |  ".join(_fparts)

        title_line = f"Histograma temporal — {metric}  [{bucket.lower()}s]"
        if _subtitle:
            title_line += f"\n{_subtitle}"
        ax.set_title(
            title_line, fontsize=10 if _subtitle else 11, pad=8, color="#222222"
        )
        self._fig.tight_layout()
        self._canvas_mpl.draw()
        self._status_var.set(
            f"Histograma temporal: {parsed_rows:,} filas · {n} intervalos · {bucket}"
        )
        self._nb.select(self._tab_analysis)

    def _generate_histogram_view(self):
        if not self._all_rows or not self._csv_columns:
            messagebox.showwarning("Sin datos", "Carga primero un CSV para analizarlo.")
            return
        if "timestamp" not in self._csv_columns:
            messagebox.showerror(
                "Sin timestamp", "El CSV no contiene la columna 'timestamp'."
            )
            return

        bucket = self._hist_bucket_var.get()
        metric = self._hist_metric_var.get()
        series_field = self._hist_series_col_var.get().strip()
        vendor_filter = self._hist_vendor_var.get().strip()
        filter1_field = self._hist_filter1_field_var.get().strip()
        filter1_value = self._hist_filter1_value_var.get().strip()
        filter2_field = self._hist_filter2_field_var.get().strip()
        filter2_value = self._hist_filter2_value_var.get().strip()
        from_value = self._hist_from_var.get().strip()
        to_value = self._hist_to_var.get().strip()

        if series_field != _NO_SERIES_FIELD and not self._field_exists_for_analysis(
            series_field
        ):
            messagebox.showerror(
                "Campo no disponible", f"La serie '{series_field}' no existe."
            )
            return

        if from_value and self._parse_time_bound(from_value) is None:
            messagebox.showerror(
                "Fecha inválida", "No se pudo interpretar la fecha 'Desde'."
            )
            return
        if to_value and self._parse_time_bound(to_value, is_end=True) is None:
            messagebox.showerror(
                "Fecha inválida", "No se pudo interpretar la fecha 'Hasta'."
            )
            return

        metric_idx = None
        if metric != "Recuento":
            metric_name = metric.replace("Suma ", "")
            if metric_name not in self._csv_columns:
                messagebox.showerror(
                    "Métrica no disponible", f"No existe la columna '{metric_name}'."
                )
                return
            metric_idx = self._csv_columns.index(metric_name)

        rows = self._get_rows_with_filters(
            self._all_rows,
            vendor_filter=vendor_filter,
            filter1_field=filter1_field,
            filter1_value=filter1_value,
            filter2_field=filter2_field,
            filter2_value=filter2_value,
            ioc_only=self._hist_ioc_only_var.get(),
            from_value=from_value,
            to_value=to_value,
        )
        if not rows:
            messagebox.showwarning(
                "Sin datos", "No hay filas que cumplan los filtros seleccionados."
            )
            return

        timestamp_idx = self._csv_columns.index("timestamp")
        grouped: dict = defaultdict(lambda: defaultdict(float))
        series_totals: Counter = Counter()
        parsed_rows = 0
        for row in rows:
            dt = _parse_timestamp(row[timestamp_idx])
            if dt is None:
                continue
            bucket_dt = _floor_timestamp(dt, bucket)
            if series_field == _NO_SERIES_FIELD:
                series_value = "Total"
            else:
                series_value = self._get_row_value(row, series_field) or "(vacío)"
                if self._hist_exclude_empty_var.get() and series_value == "(vacío)":
                    continue
            value = 1 if metric_idx is None else _safe_float(row[metric_idx])
            grouped[bucket_dt][series_value] += value
            series_totals[series_value] += value
            parsed_rows += 1

        if not grouped:
            messagebox.showwarning(
                "Sin serie temporal",
                "No hay timestamps válidos tras aplicar los filtros.",
            )
            return

        series_names = [name for name, _ in series_totals.most_common()]
        if series_field != _NO_SERIES_FIELD and not self._hist_topn_all.get():
            try:
                topn = int(self._hist_topn_var.get())
            except ValueError:
                topn = 8
            series_names = series_names[:topn]

        if not series_names:
            series_names = ["Total"]

        ordered_buckets = sorted(grouped.keys())
        labels = [_format_bucket(bucket_dt, bucket) for bucket_dt in ordered_buckets]
        series_matrix = {
            name: [grouped[bucket_dt].get(name, 0.0) for bucket_dt in ordered_buckets]
            for name in series_names
        }

        tree = self._hist_tree
        tree.delete(*tree.get_children())
        tree["columns"] = ("serie", "total", "% total")
        for name, width in (("serie", 220), ("total", 100), ("% total", 80)):
            tree.heading(name, text=name)
            tree.column(name, width=width, minwidth=70)
        grand_total = sum(series_totals[name] for name in series_names) or 1
        for name in series_names:
            total_value = series_totals[name]
            disp = (
                f"{total_value:,.0f}"
                if total_value == int(total_value)
                else f"{total_value:,.1f}"
            )
            tree.insert(
                "",
                "end",
                values=(name, disp, f"{(total_value / grand_total) * 100:.1f}%"),
            )

        if self._hist_canvas_mpl is not None:
            self._hist_fig.clear()
            ax = self._hist_fig.add_subplot(111)
            x_pos = list(range(len(labels)))
            pretty_labels = [_truncate_label(label, 22) for label in labels]
            colors = (_CHART_COLORS * ((len(series_names) // len(_CHART_COLORS)) + 1))[
                : len(series_names)
            ]

            if len(series_names) == 1:
                values = series_matrix[series_names[0]]
                ax.bar(x_pos, values, color=colors[0], width=0.82)
            else:
                bottoms = [0.0] * len(labels)
                for idx, name in enumerate(series_names):
                    values = series_matrix[name]
                    ax.bar(
                        x_pos,
                        values,
                        bottom=bottoms,
                        color=colors[idx],
                        width=0.82,
                        label=_truncate_label(name, 24),
                    )
                    bottoms = [bottoms[i] + values[i] for i in range(len(values))]
                ax.legend(fontsize=8, ncol=2, loc="upper left")

            self._style_axis(ax, value_axis="y")
            step = max(1, len(labels) // 18)
            ax.set_xticks(x_pos[::step])
            ax.set_xticklabels(
                pretty_labels[::step], rotation=38, ha="right", fontsize=8
            )
            ax.set_ylabel(metric, fontsize=9)
            subtitle = self._build_filter_subtitle(
                vendor_filter,
                filter1_field,
                filter1_value,
                filter2_field,
                filter2_value,
                ioc_only=self._hist_ioc_only_var.get(),
                from_value=from_value,
                to_value=to_value,
            )
            title = f"Histograma por {bucket.lower()}"
            if series_field != _NO_SERIES_FIELD:
                title += f" · serie={series_field}"
            title += f" — {metric}"
            if subtitle:
                ax.set_title(
                    f"{title}\n{subtitle}", fontsize=10, pad=8, color="#222222"
                )
            else:
                ax.set_title(title, fontsize=11, pad=10, color="#222222")
            self._hist_fig.tight_layout()
            self._hist_canvas_mpl.draw()

        self._hist_status_var.set(
            f"Histograma: {parsed_rows:,} filas válidas · {len(ordered_buckets)} intervalos · {len(series_names)} series"
        )
        self._nb.select(self._tab_histograms)

    def _export_hist_chart(self):
        if not _HAS_MPL or self._hist_canvas_mpl is None:
            messagebox.showwarning("Sin gráfico", "Genera primero un histograma.")
            return
        if not self._hist_fig.get_axes():
            messagebox.showwarning("Sin gráfico", "Genera primero un histograma.")
            return
        path = filedialog.asksaveasfilename(
            title="Exportar histograma",
            defaultextension=".png",
            filetypes=[
                ("PNG (alta calidad)", "*.png"),
                ("PDF vectorial", "*.pdf"),
                ("SVG vectorial", "*.svg"),
                ("JPEG", "*.jpg"),
            ],
        )
        if not path:
            return
        try:
            self._hist_fig.savefig(path, dpi=150, bbox_inches="tight")
            messagebox.showinfo("Exportado", f"Histograma guardado en:\n{path}")
        except Exception as exc:
            messagebox.showerror("Error al exportar", str(exc))

    def _export_chart(self):
        if not _HAS_MPL or self._canvas_mpl is None:
            messagebox.showwarning("Sin gráfico", "Genera primero un gráfico.")
            return
        if not self._fig.get_axes():
            messagebox.showwarning("Sin gráfico", "Genera primero un gráfico.")
            return
        path = filedialog.asksaveasfilename(
            title="Exportar gráfico",
            defaultextension=".png",
            filetypes=[
                ("PNG (alta calidad)", "*.png"),
                ("PDF vectorial", "*.pdf"),
                ("SVG vectorial", "*.svg"),
                ("JPEG", "*.jpg"),
            ],
        )
        if not path:
            return
        try:
            self._fig.savefig(path, dpi=150, bbox_inches="tight")
            messagebox.showinfo("Exportado", f"Gráfico guardado en:\n{path}")
        except Exception as exc:
            messagebox.showerror("Error al exportar", str(exc))


# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    # ── Sin argumentos → GUI ─────────────────────────────────────────────────
    if len(sys.argv) == 1:
        if not _HAS_TK:
            print(
                "[!] tkinter no disponible. Usa argumentos de línea de comandos.",
                file=sys.stderr,
            )
            sys.exit(1)
        root = tk.Tk()
        MasterOfParserGUI(root)
        root.mainloop()
        return

    parser = argparse.ArgumentParser(
        description="Parsea logs PaloAlto (LEEF 2.0) y Fortinet de QRadar → CSV CIM + IOC enrichment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Flujo recomendado:
  Paso 1 - Extraer IPs únicas del log (src + dst):
    python MasterOfParser.py "todo marzo.csv" --extract-ips ips_para_iocs.txt

  Paso 2 - Meter ips_para_iocs.txt en IOCsOfSpades → genera ULTRA CSV

  Paso 3 - Parsear y enriquecer con el resultado de IOCsOfSpades:
    python MasterOfParser.py "todo marzo.csv" --ioc-csv 20260401-1741_ULTRA.csv

    Paso 3a - Añadir OSINT en paralelo:
        python MasterOfParser.py "todo marzo.csv" --ioc-csv 20260401-1741_ULTRA.csv --osint-csv 20260401-1641_ULTRA_OSINT.csv

  Paso 3b - Solo filas con hit IOC:
    python MasterOfParser.py "todo marzo.csv" --ioc-csv 20260401-1741_ULTRA.csv --ioc-only

  Especificar fichero de salida:
    python MasterOfParser.py "todo marzo.csv" --ioc-csv ULTRA.csv --output marzo_CIM.csv
        """,
    )
    parser.add_argument("log_file", help="Fichero de log raw a parsear (LEEF 2.0)")
    parser.add_argument(
        "--ioc-csv",
        help="CSV de IOCsOfSpades (ULTRA/DOMAINS) para enriquecimiento de IOCs",
    )
    parser.add_argument(
        "--osint-csv",
        help="CSV OSINT de IOCsOfSpades para enriquecer y reforzar el scoring IOC",
    )
    parser.add_argument(
        "--extract-ips",
        help="Extraer IPs únicas (src+dst) a este fichero, para alimentar IOCsOfSpades",
    )
    parser.add_argument(
        "--output", help="Fichero CSV de salida (por defecto: TIMESTAMP_CIM_PARSED.csv)"
    )
    parser.add_argument(
        "--ioc-only",
        action="store_true",
        help="Incluir solo filas donde src_ip o dest_ip tienen match en el IOC CSV",
    )
    parser.add_argument(
        "--raw-event",
        action="store_true",
        help="Incluir la columna raw_event con la línea original completa (más pesado)",
    )
    parser.add_argument(
        "--forti-src-zone-mode",
        choices=["ssid", "interface"],
        default="ssid",
        help="Cómo normalizar src_zone en Fortinet: ssid (WiFi) o interface (srcintf)",
    )
    args = parser.parse_args()

    # ── Validar entrada ───────────────────────────────────────────────────────
    if not os.path.isfile(args.log_file):
        print(f"[!] No encontrado: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    # ── Cargar IOC/OSINT CSV (output de IOCsOfSpades) ───────────────────────
    ioc_set: set = set()  # IPs presentes en el ULTRA CSV (para hit rápido)
    ioc_map: dict = {}
    vt_map: dict = {}
    osint_map: dict = {}

    if args.ioc_csv:
        if os.path.isfile(args.ioc_csv):
            vt_map = load_iocs_csv(args.ioc_csv)
            print(f"[+] IOC CSV:   {len(vt_map):,} IPs  ({args.ioc_csv})")
        else:
            print(f"[!] --ioc-csv no encontrado: {args.ioc_csv}", file=sys.stderr)

    if args.osint_csv:
        if os.path.isfile(args.osint_csv):
            osint_map = load_osint_csv(args.osint_csv)
            print(f"[+] OSINT CSV: {len(osint_map):,} IPs  ({args.osint_csv})")
        else:
            print(f"[!] --osint-csv no encontrado: {args.osint_csv}", file=sys.stderr)

    if vt_map and osint_map:
        ioc_map = merge_ioc_maps(vt_map, osint_map)
        ioc_set = set(ioc_map.keys())
        print(f"[+] IOC merge: {len(ioc_map):,} IPs únicas (VT + OSINT)")
    elif vt_map:
        ioc_map = vt_map
        ioc_set = set(ioc_map.keys())
    elif osint_map:
        ioc_map = osint_map
        ioc_set = set(ioc_map.keys())

    # ── Fichero de salida (BOM UTF-8 para Excel) ──────────────────────────────
    ts = datetime.now().strftime("%Y%m%d-%H%M")
    output_file = args.output or f"{ts}_CIM_PARSED.csv"
    output_columns = _get_output_columns(args.raw_event)

    # ── Contar líneas para progreso ───────────────────────────────────────────
    print(f"[+] Leyendo:   {args.log_file}")
    total_lines = sum(
        1 for _ in open(args.log_file, encoding="utf-8", errors="replace")
    )
    print(f"[+] Líneas:    {total_lines:,}")
    if args.raw_event:
        print("[+] raw_event: activado (salida más pesada)")
    print(f"[+] Forti src_zone: {args.forti_src_zone_mode}")

    # ── Parsear ───────────────────────────────────────────────────────────────
    parsed = 0
    skipped = 0
    ioc_hits = 0
    vendor_counts: Counter = Counter()
    ioc_hits_by_vendor: Counter = Counter()
    last_pct = -1
    unique_ips: set = set()  # para --extract-ips

    with (
        open(args.log_file, encoding="utf-8", errors="replace") as fin,
        open(output_file, "w", newline="", encoding="utf-8-sig") as fout,
    ):
        writer = csv.DictWriter(fout, fieldnames=output_columns, extrasaction="ignore")
        writer.writeheader()

        for i, line in enumerate(fin, 1):
            # Progreso cada 5%
            pct = (i * 100) // total_lines
            if pct % 5 == 0 and pct != last_pct:
                print(f"    {pct:3d}%  ({i:,}/{total_lines:,})", end="\r")
                last_pct = pct

            line = line.strip()
            if not line:
                continue

            record = parse_line(line)
            if not record:
                skipped += 1
                continue

            record = unify_cim_record(record, args.forti_src_zone_mode)

            vendor_name = record.get("vendor", "(sin_vendor)")
            vendor_counts[vendor_name] += 1

            src_ip = record.get("src_ip", "")
            dest_ip = record.get("dest_ip", "")

            # Acumular IPs únicas para --extract-ips
            if args.extract_ips:
                if src_ip:
                    unique_ips.add(src_ip)
                if dest_ip:
                    unique_ips.add(dest_ip)

            # Enriquecimiento IOC
            record.update(enrich_ioc(src_ip, ioc_set, ioc_map, "src"))
            record.update(enrich_ioc(dest_ip, ioc_set, ioc_map, "dst"))

            has_ioc = record.get("ioc_src") == "YES" or record.get("ioc_dst") == "YES"
            if has_ioc:
                ioc_hits += 1
                ioc_hits_by_vendor[vendor_name] += 1

            if args.ioc_only and not has_ioc:
                continue

            # Escribir fila CIM
            if args.raw_event:
                record["raw_event"] = line
            writer.writerow({col: record.get(col, "") for col in output_columns})
            parsed += 1

    # ── Exportar IPs únicas para IOCsOfSpades ────────────────────────────────
    if args.extract_ips and unique_ips:
        with open(args.extract_ips, "w", encoding="utf-8") as f:
            for ip in sorted(unique_ips):
                f.write(ip + "\n")
        print(f"\n[+] IPs únicas: {len(unique_ips):,}  →  {args.extract_ips}")

    # ── Resumen ───────────────────────────────────────────────────────────────
    print()
    print("-" * 50)
    print(f"[+] Procesados: {parsed + skipped:,}")
    print(f"[+] Exportados: {parsed:,} registros CIM")
    print(f"[+] Ignorados:  {skipped:,} líneas (formato no reconocido)")
    print(f"[+] IOC hits:   {ioc_hits:,} registros (src o dst con señal IOC maliciosa)")
    if vendor_counts:
        summary_vendor = " | ".join(
            f"{vendor}: {count:,}" for vendor, count in vendor_counts.most_common()
        )
        print(f"[+] Fuentes:    {summary_vendor}")
    if ioc_hits_by_vendor:
        summary_ioc_vendor = " | ".join(
            f"{vendor}: {count:,}" for vendor, count in ioc_hits_by_vendor.most_common()
        )
        print(f"[+] IOC por fuente: {summary_ioc_vendor}")
    print(f"[+] Salida:     {output_file}")
    print("-" * 50)


if __name__ == "__main__":
    main()
