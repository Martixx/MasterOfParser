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
import io
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
    import pandas as pd

    _HAS_PANDAS = True
except ImportError:
    _HAS_PANDAS = False

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
    "TimeReceived": "timestamp",
    # Red - origen
    "src": "src_ip",
    "srcPostNAT": "src_ip_nat",
    "srcPort": "src_port",
    "SourceZone": "src_zone",
    "FromZone": "src_zone",
    "SrcHostname": "src_host",
    "vSrcName": "src_host",
    "SrcMac": "src_mac",
    "IngressInterface": "inbound_interface",
    "InboundInterface": "inbound_interface",
    # Red - destino
    "dst": "dest_ip",
    "dstPostNAT": "dest_ip_nat",
    "dstPort": "dest_port",
    "DestinationZone": "dest_zone",
    "ToZone": "dest_zone",
    "DstHostname": "dest_host",
    "DstMac": "dest_mac",
    "EgressInterface": "outbound_interface",
    "OutboundInterface": "outbound_interface",
    # Protocolo / Aplicación
    "proto": "transport",
    "Application": "app",
    "URLCategory": "url_category",
    "URLCategoryList": "url_category",
    "URL": "url",
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
    "Action": "action",
    # Regla / Política
    "RuleName": "rule",
    "Rule": "rule",
    "RuleUUID": "rule_uuid",
    "ActionSource": "action_source",
    "SessionEndReason": "session_end_reason",
    "cat": "event_category",
    "VendorSeverity": "severity",
    "DirectionOfAttack": "attack_direction",
    # Dispositivo
    "DeviceName": "dvc",
    "SerialNumber": "dvc_serial",
    "DeviceSN": "dvc_serial",
    "VirtualSystem": "virtual_system",
    "VirtualLocation": "virtual_system",
    "Subtype": "subtype",
    "SubType": "subtype",
    "SrcDeviceOS": "src_os",
    # Sesión
    "SessionID": "session_id",
    "RepeatCount": "repeat_count",
    "Flags": "flags",
    "sequence": "sequence",
    "SequenceNo": "sequence",
    # Threat intelligence (EDL, DAG, etc.)
    "SrcEDL": "src_edl",
    "DstEDL": "dest_edl",
    "SrcDAG": "src_dag",
    "DstDAG": "dest_dag",
    # Geo (PaloAlto/LEEF variants)
    "SrcCountry": "src_country",
    "SourceCountry": "src_country",
    "SourceLocation": "src_country",
    "src_country": "src_country",
    "srccountry": "src_country",
    "DstCountry": "dest_country",
    "DestinationCountry": "dest_country",
    "DestinationLocation": "dest_country",
    "dst_country": "dest_country",
    "dstcountry": "dest_country",
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
    "srcserver": "src_host",
    "dstserver": "dest_host",
    # UTM webfilter: URL accedida
    "url": "url",
    # Contexto de traducción/disposición de tráfico (snat, dnat, etc.)
    "trandisp": "action_source",
}

# Columnas CIM de salida (orden para Excel)
CIM_COLUMNS = [
    # ── QRadar (columnas del export TSV) ───────────────────────────────────
    "source_network",
    "qradar_event_name",
    "qradar_log_source",
    "qradar_category",
    "qradar_src_ip",
    "qradar_src_port",
    "qradar_dest_ip",
    "qradar_dest_port",
    "qradar_dest_country",
    "qradar_src_zone",
    "qradar_src_asset",
    "qradar_src_network_group",
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
    "event_category",
    "severity",
    "severity_bucket",
    "attack_direction",
    "ips_event",
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
    # ── Report view (aliases + clasificación) ──────────────────────────────
    "proto",
    "zone_src",
    "zone_dst",
    "interface_src",
    "interface_dst",
    "action_raw",
    "action_normalized",
    "rule_name",
    "category",
    "is_threat",
    "is_url_filter",
    "is_ips",
    "is_dns",
    "is_traffic",
    "dst_region",
    "is_CN",
    "is_RU",
    "dst_cloud_provider",
    "nat_src",
    "nat_dst",
    "bytes_sent",
    "bytes_received",
    "packets_sent",
    "packets_received",
    "ssl_inspected",
    "device_type",
    "event_type",
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
    "ioc_src_bad",
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
    "ioc_dst_bad",
    "raw_event",
]


def _get_output_columns(
    include_raw_event: bool = False,
    extra_columns: list[str] | None = None,
    include_vt: bool = True,
    include_osint: bool = True,
) -> list[str]:
    cols = list(CIM_COLUMNS)

    if not include_vt:
        vt_ioc_cols = {
            "ioc_src",
            "ioc_dst",
            "ioc_src_risk",
            "ioc_dst_risk",
            "ioc_src_country",
            "ioc_dst_country",
            "ioc_src_owner",
            "ioc_dst_owner",
            "ioc_src_asn",
            "ioc_dst_asn",
            "ioc_src_reputation",
            "ioc_dst_reputation",
            "ioc_src_malicious",
            "ioc_dst_malicious",
            "ioc_src_vendors",
            "ioc_dst_vendors",
            "ioc_src_cluster",
            "ioc_dst_cluster",
            "ioc_src_source",
            "ioc_dst_source",
            "ioc_src_vt_vendor",
            "ioc_dst_vt_vendor",
            "ioc_src_bad",
            "ioc_dst_bad",
        }
        cols = [c for c in cols if c not in vt_ioc_cols]

    if not include_osint:
        osint_cols = {
            "ioc_src_osint_hits",
            "ioc_dst_osint_hits",
            "ioc_src_osint_sources",
            "ioc_dst_osint_sources",
        }
        cols = [c for c in cols if c not in osint_cols]

    if extra_columns:
        for col in extra_columns:
            if col not in cols:
                if "raw_event" in cols:
                    cols.insert(cols.index("raw_event"), col)
                else:
                    cols.append(col)
    if include_raw_event:
        return cols
    return [col for col in cols if col != "raw_event"]


def _collect_ioc_row_keys(ioc_map: dict) -> list[str]:
    keys: set[str] = set()
    for row in ioc_map.values():
        for key in row.keys():
            norm = _normalize_csv_key(key)
            if norm and norm != "ip":
                keys.add(norm)
    return sorted(keys)


def _build_ioc_raw_output_columns(ioc_raw_keys: list[str]) -> list[str]:
    cols: list[str] = []
    for key in ioc_raw_keys:
        cols.append(f"ioc_src_raw_{key}")
        cols.append(f"ioc_dst_raw_{key}")
    return cols


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

    def _is_numeric_event_token(value: str) -> bool:
        # QRadar a veces envía EventID como "9999" o "(9999)".
        return bool(re.fullmatch(r"[\s()\[\]{}-]*\d+[\s()\[\]{}-]*", value or ""))

    # Guardar acción cruda antes de normalizaciones.
    record["action_raw"] = str(record.get("action", "") or "").strip()

    # Si el KV aporta un action numérico (QRadar Event ID), descartarlo.
    action_value = str(record.get("action", "") or "").strip()
    if _is_numeric_event_token(action_value):
        record["action"] = ""

    # El EventID del header en QRadar puede venir como "9999" o "(9999)".
    eventid_is_numeric = _is_numeric_event_token(leef_event_id)
    # Si el KV no aportó acción, usar el EventID del header solo si no es numérico
    if not record.get("action"):
        record["action"] = leef_event_id if not eventid_is_numeric else ""

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

    record["action_raw"] = str(kv.get("action", "") or "").strip()

    # Fallback útil cuando no viene policyname legible.
    if not str(record.get("rule", "") or "").strip():
        policy_id = str(kv.get("policyid", "") or "").strip()
        if policy_id:
            record["rule"] = policy_id

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
        "action_raw": "no-matching-connection",
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
# Detección formato QRadar TSV
# ─────────────────────────────────────────────────────────────────────────────
_QRADAR_HEADER_MAP = {
    "Hora inicio": None,  # timestamp se extrae del payload (más preciso)
    "Nombre suceso": "qradar_event_name",
    "Origen de registro": "qradar_log_source",
    "Categor\u00eda nivel bajo": "qradar_category",
    "IP de Origen": "qradar_src_ip",
    "Puerto de origen": "qradar_src_port",
    "Ip de destino": "qradar_dest_ip",
    "Puerto destino": "qradar_dest_port",
    "Pais destino": "qradar_dest_country",
    "Source_Network": "source_network",
    "Source zone": "qradar_src_zone",
    "Nombre activo Origen": "qradar_src_asset",
    "Grupo de red de origen": "qradar_src_network_group",
}
_QRADAR_PAYLOAD_COL = "Payload"


def detect_qradar_tsv(path: str) -> tuple[list[str], str] | None:
    """Lee la primera línea del fichero. Si contiene 'Payload' como cabecera,
    devuelve (lista de cabeceras, delimitador). Si no, devuelve None (raw syslog).
    Prueba primero coma, luego tab (coma genera más columnas en exports QRadar)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        first_line = f.readline()
    best = None
    for delim in (",", "\t"):
        cols = first_line.strip().split(delim)
        if _QRADAR_PAYLOAD_COL in cols and len(cols) >= 5:
            if best is None or len(cols) > len(best[0]):
                best = (cols, delim)
    return best


def _split_qradar_line(line: str, ncols: int, delim: str) -> list[str]:
    """Divide una línea QRadar respetando que el Payload (última columna) puede
    contener el delimitador internamente (ej. comas dentro de LEEF)."""
    # Partimos en ncols-1 splits: las primeras N-1 columnas + todo el resto es Payload
    return line.split(delim, ncols - 1)


def _extract_qradar_fields(tsv_cols: list[str], parts: list[str]) -> dict:
    """Dado un split de una línea QRadar, devuelve dict con campos mapeados."""
    extra: dict = {}
    for i, col_name in enumerate(tsv_cols):
        if i >= len(parts):
            break
        cim_name = _QRADAR_HEADER_MAP.get(col_name)
        if cim_name:
            extra[cim_name] = parts[i].strip()
    return extra


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


def _normalize_csv_key(key: str) -> str:
    return str(key or "").replace("\ufeff", "").strip().lower()


def _read_csv_dict_rows(path: str) -> tuple[set[str], list[dict]]:
    """Lee CSV tolerando BOM y delimitador típico de Excel (; o ,)."""
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        sample = f.read(4096)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            reader = csv.DictReader(f, dialect=dialect)
        except csv.Error:
            reader = csv.DictReader(f)

        rows: list[dict] = []
        headers = {_normalize_csv_key(h) for h in (reader.fieldnames or [])}
        for raw in reader:
            normalized = {
                _normalize_csv_key(k): str(v or "").strip() for k, v in raw.items()
            }
            rows.append(normalized)
    return headers, rows


def _extract_ioc_ip(row: dict) -> str:
    for key in ("ip", "ip_address", "ipaddress", "indicator", "ioc"):
        value = str(row.get(key, "") or "").strip()
        if value:
            return value
    return ""


def load_iocs_csv(path: str) -> dict:
    """
    Carga un CSV de IOCsOfSpades (ULTRA / DOMAINS) en un dict { ip -> row }.
    Gestiona celdas multilínea (whois) con csv.DictReader.
    """
    ioc_map: dict = {}
    _, rows = _read_csv_dict_rows(path)
    for row in rows:
        ip = _extract_ioc_ip(row)
        if ip:
            ioc_map[ip] = row
    return ioc_map


def load_osint_csv(path: str) -> dict:
    """Carga un CSV OSINT en un dict { ip -> row } para fusionarlo con VT."""
    osint_map: dict = {}
    _, rows = _read_csv_dict_rows(path)
    for row in rows:
        ip = _extract_ioc_ip(row)
        if ip:
            osint_map[ip] = row
    return osint_map


def detect_ioc_csv_kind(path: str) -> str:
    """Detecta si un CSV es VT ULTRA, ULTRA_OSINT o desconocido por cabeceras."""
    try:
        headers, _ = _read_csv_dict_rows(path)
    except OSError:
        return "unknown"

    vt_markers = {"risk_score", "malicious", "vendors_malicious", "cluster_flag"}
    osint_markers = {
        "verdict",
        "asn_drop",
        "bl_dshield_targets",
        "abuseipdb_score",
        "threatfox_confidence",
        "urlhaus_url_count",
        "otx_pulses",
    }
    has_vt = bool(headers & vt_markers)
    has_osint = bool(headers & osint_markers)

    if has_vt and not has_osint:
        return "vt"
    if has_osint and not has_vt:
        return "osint"
    if has_vt and has_osint:
        return "mixed"
    return "unknown"


def load_ioc_sources(
    ioc_csv: str | None, osint_csv: str | None
) -> tuple[dict, dict, list[str]]:
    """Carga y clasifica fuentes IOC (VT/OSINT) tolerando rutas cruzadas."""
    vt_map: dict = {}
    osint_map: dict = {}
    logs: list[str] = []

    for label, path in (("IOC", ioc_csv), ("OSINT", osint_csv)):
        if not path:
            continue
        kind = detect_ioc_csv_kind(path)
        if kind == "vt":
            loaded = load_iocs_csv(path)
            vt_map.update(loaded)
            logs.append(f"[+] {label} CSV (VT ULTRA):   {len(loaded):,} IPs  ({path})")
            if not loaded:
                logs.append(
                    f"[!] {label} CSV sin IPs leíbles. Revisa delimitador/cabecera 'ip' ({path})"
                )
        elif kind == "osint":
            loaded = load_osint_csv(path)
            osint_map.update(loaded)
            logs.append(f"[+] {label} CSV (ULTRA_OSINT): {len(loaded):,} IPs  ({path})")
            if not loaded:
                logs.append(
                    f"[!] {label} CSV sin IPs leíbles. Revisa delimitador/cabecera 'ip' ({path})"
                )
        elif kind == "mixed":
            vt_loaded = load_iocs_csv(path)
            osint_loaded = load_osint_csv(path)
            vt_map.update(vt_loaded)
            osint_map.update(osint_loaded)
            logs.append(
                f"[+] {label} CSV (mixto): VT={len(vt_loaded):,} / OSINT={len(osint_loaded):,} IPs  ({path})"
            )
        else:
            # Fallback conservador: intentar ambas lecturas para no perder enriquecimiento.
            vt_loaded = load_iocs_csv(path)
            osint_loaded = load_osint_csv(path)
            if len(vt_loaded) >= len(osint_loaded):
                vt_map.update(vt_loaded)
                logs.append(
                    f"[+] {label} CSV (auto→VT):   {len(vt_loaded):,} IPs  ({path})"
                )
            else:
                osint_map.update(osint_loaded)
                logs.append(
                    f"[+] {label} CSV (auto→OSINT): {len(osint_loaded):,} IPs  ({path})"
                )

    return vt_map, osint_map, logs


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
    "_bad",
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


def _osint_get(row: dict, key: str, default: str = "") -> str:
    """Lee campos OSINT con o sin prefijo osint_ para soportar ambos formatos."""
    return str(row.get(f"osint_{key}", row.get(key, default)) or "").strip()


def _pick_source(row: dict) -> str:
    osint_verdict = _osint_get(row, "verdict").lower()
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

    osint_hits = _to_int(_osint_get(row, "bl_dshield_targets"))
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
    verdict = _osint_get(row, "verdict").lower()
    if verdict in {"malicious", "suspicious"}:
        return True

    if _osint_get(row, "asn_drop").lower() == "yes":
        return True

    bool_flags = [
        "bl_dshield_24",
        "bl_blocklistde_48h",
        "bl_feodo",
        "bl_cinsscore",
        "bl_et_compromised",
        "abuseipdb_is_tor",
    ]
    for key in bool_flags:
        if _osint_get(row, key).lower() == "yes":
            return True

    numeric_fields = [
        "bl_dshield_targets",
        "abuseipdb_score",
        "abuseipdb_reports",
        "threatfox_confidence",
        "urlhaus_url_count",
        "otx_pulses",
    ]
    for key in numeric_fields:
        if _to_int(_osint_get(row, key)) > 0:
            return True

    malware_name = _osint_get(row, "threatfox_malware")
    if malware_name and "error:" not in malware_name.lower():
        return True

    return False


def _collect_osint_sources(row: dict) -> list[str]:
    sources: list[str] = []

    if _osint_get(row, "asn_drop").lower() == "yes":
        source = _osint_get(row, "asn_drop_source")
        sources.append(source or "asn_drop")

    if (
        _osint_get(row, "bl_dshield_24").lower() == "yes"
        or _to_int(_osint_get(row, "bl_dshield_targets")) > 0
    ):
        sources.append("dshield")
    if _osint_get(row, "bl_blocklistde_48h").lower() == "yes":
        sources.append("blocklistde")
    if _osint_get(row, "bl_feodo").lower() == "yes":
        sources.append("feodo")
    if _osint_get(row, "bl_cinsscore").lower() == "yes":
        sources.append("cinsscore")
    if _osint_get(row, "bl_et_compromised").lower() == "yes":
        sources.append("et_compromised")

    if (
        _to_int(_osint_get(row, "abuseipdb_score")) > 0
        or _to_int(_osint_get(row, "abuseipdb_reports")) > 0
    ):
        sources.append("abuseipdb")
    if _to_int(_osint_get(row, "threatfox_confidence")) > 0 or _osint_get(
        row, "threatfox_malware"
    ):
        malware = _osint_get(row, "threatfox_malware").lower()
        if "error:" not in malware:
            sources.append("threatfox")
    if _to_int(_osint_get(row, "urlhaus_url_count")) > 0:
        sources.append("urlhaus")
    if _to_int(_osint_get(row, "otx_pulses")) > 0:
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


def _ioc_quality_label(row: dict | None, in_list: bool) -> str:
    """Clasifica IOC en bueno/sospechoso/malo combinando VT y OSINT."""
    if not row:
        return "sospechoso" if in_list else ""

    verdict = _osint_get(row, "verdict").lower()
    if verdict == "malicious":
        return "malo"
    if verdict == "suspicious":
        return "sospechoso"
    if verdict == "clean":
        return "bueno"

    if _to_int(row.get("malicious")) > 0:
        return "malo"
    if _to_int(row.get("suspicious")) > 0:
        return "sospechoso"
    if str(row.get("vendors_malicious", "")).strip():
        return "malo"

    risk = _to_int(row.get("risk_score"))
    if risk >= 70:
        return "malo"
    if risk >= 40:
        return "sospechoso"

    if _has_osint_positive(row):
        return "sospechoso"

    if in_list:
        return "bueno"
    return ""


def enrich_ioc(
    ip: str,
    ioc_set: set,
    ioc_map: dict,
    prefix: str,
    ioc_raw_keys: list[str] | None = None,
) -> dict:
    """Devuelve campos de enriquecimiento IOC para una IP dada."""
    result = _empty_ioc(prefix)
    for key in ioc_raw_keys or []:
        result[f"ioc_{prefix}_raw_{key}"] = ""
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
        result[f"ioc_{prefix}_bad"] = _ioc_quality_label(row, in_list)
        for key in ioc_raw_keys or []:
            result[f"ioc_{prefix}_raw_{key}"] = str(row.get(key, "") or "")
    elif in_list:
        result[f"ioc_{prefix}_bad"] = _ioc_quality_label(row, in_list)

    # IOC YES solo cuando hay señal maliciosa, no solo por aparecer en el ULTRA.
    if _is_ioc_alert(row):
        result[f"ioc_{prefix}"] = "YES"
    elif in_list:
        result[f"ioc_{prefix}"] = "NO"

    return result


def enrich_ioc_candidates(
    candidates: list[str],
    ioc_set: set,
    ioc_map: dict,
    prefix: str,
    ioc_raw_keys: list[str] | None = None,
) -> dict:
    """Enriquece IOC probando varias IP candidatas (p. ej., IP real + NAT)."""
    seen: set[str] = set()
    clean_candidates: list[str] = []
    for value in candidates:
        ip = str(value or "").strip()
        if ip and ip not in seen:
            seen.add(ip)
            clean_candidates.append(ip)

    best_no_match: dict | None = None
    for ip in clean_candidates:
        enriched = enrich_ioc(ip, ioc_set, ioc_map, prefix, ioc_raw_keys)
        verdict = enriched.get(f"ioc_{prefix}", "")
        if verdict == "YES":
            return enriched
        if verdict == "NO" and best_no_match is None:
            best_no_match = enriched

    if best_no_match is not None:
        return best_no_match
    result = _empty_ioc(prefix)
    for key in ioc_raw_keys or []:
        result[f"ioc_{prefix}_raw_{key}"] = ""
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Constantes para la pestaña Análisis
# ─────────────────────────────────────────────────────────────────────────────
_NO_SECONDARY_FIELD = "(ninguno)"
_NO_FILTER_FIELD = "(sin filtro)"
_NO_SERIES_FIELD = "(total)"
_ANALYSIS_VENDOR_OPTIONS = ["(todos)", "Palo Alto Networks", "Fortinet", "Cisco"]
_PIVOT_FIELDS = [
    "source_network",
    "qradar_event_name",
    "qradar_log_source",
    "qradar_category",
    "qradar_dest_country",
    "qradar_src_zone",
    "qradar_src_network_group",
    "vendor",
    "timestamp",
    "timestamp_date",
    "action",
    "event_category",
    "severity",
    "severity_bucket",
    "attack_direction",
    "ips_event",
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
    "ioc_src_bad",
    "ioc_dst_bad",
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
    "Barras apiladas (H)",
    "Barras apiladas (V)",
    "Heatmap",
    "Radar",
    "Sunburst",
    "Treemap",
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
# Sufijos de zona horaria que strptime no puede manejar (ej. " GMT" de QRadar LEEF)
_TZ_SUFFIX_RE = re.compile(r"\s+(?:GMT|UTC|[+-]\d{2}:?\d{2})\s*$", re.IGNORECASE)


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

    # Eliminar sufijo de zona horaria que datetime.strptime no entiende (ej. " GMT" de QRadar)
    text = _TZ_SUFFIX_RE.sub("", text)

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
            if fmt == "%b %d %H:%M:%S":
                current_year = datetime.now().year
                parsed = datetime.strptime(
                    f"{text} {current_year}", "%b %d %H:%M:%S %Y"
                )
            else:
                parsed = datetime.strptime(text, fmt)
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


def _severity_bucket(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if text in {"critical", "severe"}:
        return "critical"
    if text in {"high", "alto"}:
        return "high"
    if text in {"medium", "moderate", "med", "medio"}:
        return "medium"
    if text in {"low", "bajo"}:
        return "low"
    if text in {"informational", "info", "informativo"}:
        return "info"
    return text


def _is_ips_event(record: dict) -> bool:
    category = str(record.get("event_category", "") or "").strip().lower()
    subtype = str(record.get("subtype", "") or "").strip().lower()
    action = str(record.get("action", "") or "").strip().lower()

    ips_subtypes = {
        "vulnerability",
        "spyware",
        "virus",
        "wildfire",
        "url",
        "flood",
        "dos",
    }
    if category == "threat":
        return True
    if subtype in ips_subtypes:
        return True
    if action == "alert":
        return True
    return False


def unify_cim_record(record: dict, forti_src_zone_mode: str = "ssid") -> dict:
    """Consolida aliases/sinónimos en campos CIM canónicos."""
    if not record:
        return record

    # --- Aliases y normalización básica ---
    alias_candidates = {
        "src_ip_nat": ["src_ip_nat", "src_nat_ip", "srcPostNAT"],
        "dest_ip_nat": ["dest_ip_nat", "dst_nat_ip", "dstPostNAT"],
        "src_zone": ["src_zone", "SourceZone", "srcintf", "inbound_interface"],
        "dest_zone": ["dest_zone", "DestinationZone", "dstintf", "outbound_interface"],
        "src_host": ["src_host", "SrcHostname", "srcname", "hostname"],
        "dest_host": ["dest_host", "DstHostname", "dstname"],
        "src_country": [
            "src_country",
            "srccountry",
            "SrcCountry",
            "SourceCountry",
            "ioc_src_country",
        ],
        "dest_country": [
            "dest_country",
            "dstcountry",
            "DstCountry",
            "DestinationCountry",
            "ioc_dst_country",
        ],
        "user": ["user", "usrName", "SourceUser", "SrcUser", "srcuser", "xauthuser"],
        "rule": ["rule", "RuleName", "policyname", "policy_name"],
        "rule_uuid": ["rule_uuid", "RuleUUID", "poluuid"],
        "event_category": ["event_category", "cat", "Category"],
        "severity": ["severity", "VendorSeverity", "severity_level"],
        "attack_direction": [
            "attack_direction",
            "DirectionOfAttack",
            "direction_of_attack",
        ],
    }
    for canonical_key, candidates in alias_candidates.items():
        if not str(record.get(canonical_key, "") or "").strip():
            record[canonical_key] = _first_non_empty(record, candidates)

    # --- Zonas e interfaces ---
    wan_names = {"link_amoreiras-sines", "link_sines", "n1_to_n2"}
    for zone_key, iface_key, out_key in [
        ("src_zone", "inbound_interface", "zone_src"),
        ("dest_zone", "outbound_interface", "zone_dst"),
    ]:
        zone = str(record.get(zone_key, "") or "").strip().lower()
        iface = str(record.get(iface_key, "") or "").strip().lower()
        vd = str(record.get("vd", "") or "").strip().lower()
        if not zone or zone in wan_names or zone.startswith("link_") or vd == "root":
            record[out_key] = "UNKNOWN-WAN"
        else:
            record[out_key] = zone.upper()
        # Interfaces
        if iface:
            record[out_key.replace("zone", "interface")] = iface.upper()
        else:
            record[out_key.replace("zone", "interface")] = None

    # --- NAT ---
    record["nat_src"] = bool(record.get("src_ip_nat"))
    record["nat_dst"] = bool(record.get("dest_ip_nat"))

    # --- Normalización de acción ---
    action_raw = str(record.get("action", "") or "").strip().lower()
    subtype = str(record.get("subtype", "") or "").strip().lower()
    event_cat = str(record.get("event_category", "") or "").strip().lower()
    is_threat = subtype == "threat" or event_cat == "threat"
    is_url = subtype == "url"
    is_ips = _is_ips_event(record)
    # Mapeo estricto
    action_map = {
        "allow": "allow",
        "deny": "deny",
        "alert": "alert",
        "tcp-fin": "allow",
        "tcp-rst-from-client": "reset-client",
        "tcp-rst-from-server": "reset-server",
        "aged-out": "reset-client",
        "incomplete": "reset-client",
        "client-rst": "reset-client",
        "server-rst": "reset-server",
    }
    action_normalized = None
    if action_raw in action_map:
        action_normalized = action_map[action_raw]
    elif (is_threat or is_ips or is_url) and not action_raw:
        action_normalized = "alert"
    elif (
        not action_raw and not (is_threat or is_ips or is_url) and subtype == "traffic"
    ):
        action_normalized = "allow"
    else:
        action_normalized = None
    record["action_normalized"] = action_normalized
    record["action_raw"] = action_raw if action_raw else None

    # --- Normalización de tipo de evento ---
    if is_ips:
        record["event_type"] = "ips"
    elif subtype == "traffic":
        record["event_type"] = "traffic"
    elif subtype == "url":
        record["event_type"] = "url_filter"
    elif subtype == "threat":
        record["event_type"] = "threat"
    elif subtype.startswith("dns") or "dns" in subtype:
        record["event_type"] = "dns"
    else:
        record["event_type"] = None

    # --- Flags de tipo ---
    record["is_threat"] = "YES" if is_threat else "NO"
    record["is_url_filter"] = "YES" if is_url else "NO"
    record["is_ips"] = "YES" if is_ips else "NO"
    record["is_dns"] = "YES" if record["event_type"] == "dns" else "NO"
    record["is_traffic"] = "YES" if record["event_type"] == "traffic" else "NO"

    # --- Severidad y buckets ---
    severity_value = str(record.get("severity", "") or "").strip().lower()
    if severity_value:
        record["severity"] = severity_value
    if not str(record.get("severity_bucket", "") or "").strip():
        record["severity_bucket"] = _severity_bucket(record.get("severity", ""))

    # --- IPS extra ---
    if is_ips:
        # Solo si existen, nunca "unknown"
        for k in ["severity_bucket", "attack_direction", "event_category"]:
            v = record.get(k, None)
            if v == "unknown" or v == "":
                record[k] = None

    # --- IOC: nunca "unknown", solo null si no existe ---
    for k in list(record.keys()):
        if k.startswith("ioc_") and (record[k] == "unknown" or record[k] == ""):
            record[k] = None

    # --- NAT: true/false ---
    record["nat_src"] = bool(record.get("src_ip_nat"))
    record["nat_dst"] = bool(record.get("dest_ip_nat"))

    # --- Vacíos a null ---
    for k, v in list(record.items()):
        if v == "" or v == "unknown":
            record[k] = None

    # --- Fecha derivada ---
    timestamp_value = str(record.get("timestamp", "") or "").strip()
    if timestamp_value and not str(record.get("timestamp_date", "") or "").strip():
        parsed_ts = _parse_timestamp(timestamp_value)
        if parsed_ts is not None:
            record["timestamp_date"] = parsed_ts.strftime("%Y-%m-%d")

    # --- Totales de tráfico ---
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
        try:
            root.state("zoomed")
        except Exception:
            pass

        # ── Logo programático (tkinter Canvas, 0 RAM extra) ──────────────────
        self._set_window_icon(root)

        self._queue: queue.Queue = queue.Queue()
        self._last_output: str = ""
        self._loaded_csv_path: str = ""
        self._stop_requested = threading.Event()
        self._analysis_refresh_after_id = None
        self._hist_refresh_after_id = None
        self._analysis_zoom_stack: list[
            tuple[tuple[float, float], tuple[float, float]]
        ] = []
        self._hist_zoom_stack: list[tuple[tuple[float, float], tuple[float, float]]] = (
            []
        )

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

        status = ttk.Frame(root)
        status.pack(fill="x", side="bottom", padx=8, pady=(0, 8))
        self._global_progress = ttk.Progressbar(status, mode="determinate", maximum=100)
        self._global_progress.pack(fill="x")
        self._global_progress_var = tk.StringVar(value="Listo.")
        ttk.Label(status, textvariable=self._global_progress_var, anchor="w").pack(
            fill="x", pady=(2, 0)
        )

        self._build_parser_tab()
        self._build_results_tab()
        self._build_analysis_tab()
        self._build_histograms_tab()
        nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _set_global_progress(self, value: int, text: str = ""):
        value = max(0, min(100, int(value)))
        self._global_progress.configure(mode="determinate")
        self._global_progress["value"] = value
        if text:
            self._global_progress_var.set(text)

    def _set_global_busy(self, text: str):
        self._global_progress.configure(mode="indeterminate")
        self._global_progress.start(12)
        self._global_progress_var.set(text)

    def _finish_global_progress(self, text: str = "Listo."):
        self._global_progress.stop()
        self._global_progress.configure(mode="determinate")
        self._global_progress["value"] = 100
        self._global_progress_var.set(text)

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

        row = ttk.Frame(tab)
        row.pack(fill="x", **pad)
        ttk.Label(row, text="Relacionar IOCs", width=20, anchor="w").pack(side="left")
        self._ioc_src_var = tk.BooleanVar(value=True)
        self._ioc_dst_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="src_ip (origen)", variable=self._ioc_src_var).pack(
            side="left", padx=4
        )
        ttk.Checkbutton(row, text="dest_ip (destino)", variable=self._ioc_dst_var).pack(
            side="left", padx=4
        )

        ttk.Separator(tab, orient="horizontal").pack(fill="x", padx=8, pady=6)

        # Botones
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill="x", padx=8)
        self._run_btn = ttk.Button(btn_frame, text="▶  Ejecutar", command=self._run)
        self._run_btn.pack(side="left")
        self._pause_btn = ttk.Button(
            btn_frame,
            text="⏸  Pausar/Parar",
            state="disabled",
            command=self._request_stop,
        )
        self._pause_btn.pack(side="left", padx=(6, 0))
        self._open_results_btn = ttk.Button(
            btn_frame,
            text="Ver resultados →",
            state="disabled",
            command=self._open_results_tab,
        )
        self._open_results_btn.pack(side="left", padx=8)

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
        ttk.Button(ctrl, text="Columnas…", command=self._open_column_selector).pack(
            side="left", padx=(6, 0)
        )

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
        self._tree.bind("<ButtonPress-1>", self._on_tree_left_press, add="+")
        self._tree.bind("<B1-Motion>", self._on_tree_left_drag, add="+")
        self._tree.bind("<ButtonRelease-1>", self._on_tree_left_release, add="+")

        # Barra de estado
        self._status_var = tk.StringVar(value="Sin datos cargados")
        ttk.Label(tab, textvariable=self._status_var, anchor="w").pack(
            fill="x", padx=8, pady=2
        )

        self._all_rows: list = []
        self._csv_columns: list = []
        self._df = None  # Cache pandas DataFrame
        self._display_columns: list = []
        self._hidden_columns: set[str] = set()
        self._header_drag_col: str = ""
        self._header_drag_start_x: int = 0
        self._header_drag_active: bool = False
        self._suppress_sort_once: bool = False
        self._sort_col: str = ""
        self._sort_asc: bool = True
        self._results_filters: list[dict] = []
        # Datos exportables del último gráfico / histograma
        self._last_pivot_labels: list = []
        self._last_pivot_values: list = []
        self._last_pivot_meta: dict = {}
        self._last_hist_result: dict = {}
        # Carpeta de sesión para exportaciones
        self._session_folder: str = ""
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
        ioc_src = self._ioc_src_var.get()
        ioc_dst = self._ioc_dst_var.get()
        extract_ips = (
            self._extract_path_var.get().strip() if self._extract_var.get() else None
        )

        if ioc_csv and not os.path.isfile(ioc_csv):
            messagebox.showerror("Error", f"IOC CSV no encontrado:\n{ioc_csv}")
            return
        if osint_csv and not os.path.isfile(osint_csv):
            messagebox.showerror("Error", f"OSINT CSV no encontrado:\n{osint_csv}")
            return

        self._stop_requested.clear()
        self._run_btn.configure(state="disabled")
        self._pause_btn.configure(state="normal")
        self._open_results_btn.configure(state="disabled")
        self._set_global_progress(0, "Procesando logs... 0%")
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
                ioc_src,
                ioc_dst,
            ),
            daemon=True,
        ).start()
        self._poll()

    def _request_stop(self):
        self._stop_requested.set()
        self._pause_btn.configure(state="disabled")
        self._log("[!] Parada solicitada: deteniendo ejecución...")

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
        ioc_src,
        ioc_dst,
    ):
        q = self._queue

        def log(msg):
            q.put(("log", msg))

        try:
            ioc_set: set = set()
            ioc_map: dict = {}
            vt_map, osint_map, source_logs = load_ioc_sources(ioc_csv, osint_csv)
            for msg in source_logs:
                log(msg)

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

            ioc_raw_keys = _collect_ioc_row_keys(ioc_map)
            ioc_raw_output_columns = _build_ioc_raw_output_columns(ioc_raw_keys)
            has_vt_source = bool(vt_map)
            has_osint_source = bool(osint_map)

            ts = datetime.now().strftime("%Y%m%d-%H%M")
            output_file = output_file or f"{ts}_CIM_PARSED.csv"
            output_columns = _get_output_columns(
                include_raw_event,
                extra_columns=ioc_raw_output_columns,
                include_vt=has_vt_source,
                include_osint=has_osint_source,
            )

            log(f"[+] Leyendo:   {log_file}")
            total_lines = sum(
                1 for _ in open(log_file, encoding="utf-8", errors="replace")
            )
            log(f"[+] Líneas:    {total_lines:,}")
            if include_raw_event:
                log("[+] raw_event: activado (salida más pesada)")
            log(f"[+] Forti src_zone: {forti_src_zone_mode}")
            log(f"[+] IOC src_ip: {ioc_src}, dest_ip: {ioc_dst}")

            # Detectar formato QRadar TSV
            qradar_result = detect_qradar_tsv(log_file)
            qradar_cols = None
            qradar_delim = ","
            if qradar_result:
                qradar_cols, qradar_delim = qradar_result
                log(
                    f"[+] Formato:   QRadar ({len(qradar_cols)} columnas, delim='{qradar_delim}', Payload incluido)"
                )
                payload_idx = qradar_cols.index(_QRADAR_PAYLOAD_COL)
            else:
                log("[+] Formato:   raw syslog (una línea = un evento)")

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

                first_line_skipped = False
                for i, line in enumerate(fin, 1):
                    if self._stop_requested.is_set():
                        log("[!] Ejecución detenida por usuario.")
                        q.put(("cancelled", output_file))
                        return

                    pct = (i * 100) // total_lines
                    if pct % 5 == 0 and pct != last_pct:
                        q.put(("progress", pct))
                        last_pct = pct

                    line = line.strip()
                    if not line:
                        continue

                    # QRadar TSV: saltar cabecera y extraer campos
                    qradar_extra: dict = {}
                    if qradar_cols:
                        if not first_line_skipped:
                            first_line_skipped = True
                            continue  # saltar cabecera
                        parts = _split_qradar_line(line, len(qradar_cols), qradar_delim)
                        qradar_extra = _extract_qradar_fields(qradar_cols, parts)
                        line = parts[payload_idx] if payload_idx < len(parts) else ""
                        if not line:
                            skipped += 1
                            continue

                    record = parse_line(line)
                    if not record:
                        skipped += 1
                        continue

                    record = unify_cim_record(record, forti_src_zone_mode)

                    # Merge columnas QRadar (no sobreescriben campos del payload)
                    if qradar_extra:
                        for k, v in qradar_extra.items():
                            if v and not record.get(k):
                                record[k] = v

                    vendor_name = record.get("vendor", "(sin_vendor)")
                    vendor_counts[vendor_name] += 1

                    src_ip = record.get("src_ip", "")
                    dest_ip = record.get("dest_ip", "")

                    if extract_ips:
                        if src_ip:
                            unique_ips.add(src_ip)
                        if dest_ip:
                            unique_ips.add(dest_ip)

                    if ioc_src:
                        record.update(
                            enrich_ioc_candidates(
                                [
                                    record.get("src_ip", ""),
                                    record.get("src_ip_nat", ""),
                                ],
                                ioc_set,
                                ioc_map,
                                "src",
                                ioc_raw_keys,
                            )
                        )
                    if ioc_dst:
                        record.update(
                            enrich_ioc_candidates(
                                [
                                    record.get("dest_ip", ""),
                                    record.get("dest_ip_nat", ""),
                                ],
                                ioc_set,
                                ioc_map,
                                "dst",
                                ioc_raw_keys,
                            )
                        )

                    src_hit = record.get("ioc_src") == "YES" if ioc_src else False
                    dst_hit = record.get("ioc_dst") == "YES" if ioc_dst else False
                    has_ioc = src_hit or dst_hit
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
                    self._finish_global_progress("Proceso completado (100%).")
                    self._run_btn.configure(state="normal")
                    self._pause_btn.configure(state="disabled")
                    self._open_results_btn.configure(state="normal")
                    messagebox.showinfo("Listo", f"Fichero generado:\n{data}")
                    return
                elif kind == "cancelled":
                    self._last_output = data
                    self._finish_global_progress("Proceso detenido por usuario.")
                    self._run_btn.configure(state="normal")
                    self._pause_btn.configure(state="disabled")
                    if data and os.path.isfile(data):
                        self._open_results_btn.configure(state="normal")
                    messagebox.showinfo(
                        "Ejecución detenida",
                        f"Proceso interrumpido por usuario.\nSalida parcial:\n{data}",
                    )
                    return
                elif kind == "error":
                    self._finish_global_progress("Error durante la ejecución.")
                    self._run_btn.configure(state="normal")
                    self._pause_btn.configure(state="disabled")
                    messagebox.showerror("Error durante la ejecución", data)
                    return
                elif kind == "progress":
                    pct = int(data)
                    self._set_global_progress(pct, f"Procesando logs... {pct}%")
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _on_tab_changed(self, _event=None):
        """Al cambiar de pestaña, carga el CSV parseado si aún no está cargado."""
        selected = self._nb.select()
        # Auto-cargar CSV en cualquier pestaña que lo necesite (Resultados, Análisis, Histogramas)
        if selected != str(self._tab_parser):
            if (
                self._last_output
                and os.path.isfile(self._last_output)
                and self._last_output != self._loaded_csv_path
            ):
                self._load_csv(self._last_output)

    def _ensure_default_hist_overview(self):
        """Configura vista general por defecto en Histogramas cuando aún no hay gráfico."""
        has_chart = False
        if _HAS_MPL and hasattr(self, "_hist_fig") and self._hist_fig is not None:
            has_chart = bool(self._hist_fig.axes)
        if has_chart:
            return

        self._hist_series_col_var.set(_NO_SERIES_FIELD)
        self._hist_vendor_var.set("(todos)")
        self._hist_from_var.set("")
        self._hist_to_var.set("")
        self._hist_filter1_field_var.set(_NO_FILTER_FIELD)
        self._hist_filter1_value_var.set("")
        self._hist_filter2_field_var.set(_NO_FILTER_FIELD)
        self._hist_filter2_value_var.set("")
        self._hist_bucket_var.set("Día")
        self._hist_metric_var.set("Recuento")
        self._hist_topn_var.set("8")
        self._hist_topn_all.set(False)
        self._hist_exclude_empty_var.set(True)
        self._hist_fill_gaps_var.set(True)
        self._hist_ioc_only_var.set(False)

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

        self._status_var.set(f"Cargando {os.path.basename(path)}…")
        self._set_global_progress(0, f"Cargando CSV... 0% ({os.path.basename(path)})")

        def _read():
            try:
                fname = os.path.basename(path)
                self.root.after(
                    0,
                    lambda: self._set_global_progress(10, f"Leyendo CSV... ({fname})"),
                )
                if _HAS_PANDAS:
                    df = pd.read_csv(
                        path,
                        encoding="utf-8-sig",
                        dtype=str,
                        keep_default_na=False,
                        low_memory=False,
                    )
                    cols = df.columns.tolist()
                    rows = df.values.tolist()
                else:
                    rows = []
                    with open(path, encoding="utf-8-sig", errors="replace") as f:
                        reader = csv.DictReader(f)
                        cols = list(reader.fieldnames or [])
                        for row in reader:
                            rows.append([row.get(c, "") for c in cols])
                self.root.after(0, lambda: self._finish_csv_load(path, cols, rows))
            except Exception as exc:
                self.root.after(
                    0,
                    lambda: (
                        self._finish_global_progress("Error cargando CSV."),
                        messagebox.showerror("Error cargando CSV", str(exc)),
                    ),
                )

        threading.Thread(target=_read, daemon=True).start()

    def _finish_csv_load(self, path: str, cols: list, rows: list):
        self._set_global_progress(50, f"Preparando tabla... ({os.path.basename(path)})")
        self._loaded_csv_path = path
        self._last_output = path  # compartir con todas las pestañas
        self._csv_columns = cols
        self._display_columns = list(cols)
        self._hidden_columns = set()
        self._all_rows = rows
        # Cache DataFrame para operaciones rápidas
        if _HAS_PANDAS:
            self._df = pd.DataFrame(rows, columns=cols)
        else:
            self._df = None
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
        # Actualizar comboboxes en Análisis e Histogramas
        extra = [c for c in cols if c not in _PIVOT_FIELDS]
        analysis_fields = _DERIVED_ANALYSIS_FIELDS + _PIVOT_FIELDS + extra
        self._pivot_col_cb["values"] = analysis_fields
        self._pivot_secondary_col_cb["values"] = [_NO_SECONDARY_FIELD] + analysis_fields
        self._analysis_filter1_field_cb["values"] = [_NO_FILTER_FIELD] + analysis_fields
        self._analysis_filter2_field_cb["values"] = [_NO_FILTER_FIELD] + analysis_fields
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
        if self._hist_series_col_var.get() not in self._hist_series_col_cb["values"]:
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

    def _setup_tree(self, cols, rows):
        tree = self._tree
        tree.delete(*tree.get_children())
        tree["columns"] = cols

        desired_display = [
            col
            for col in self._display_columns
            if col in cols and col not in self._hidden_columns
        ]
        desired_display += [
            col
            for col in cols
            if col not in self._hidden_columns and col not in desired_display
        ]
        if not desired_display and cols:
            desired_display = [cols[0]]
            self._hidden_columns = set(cols[1:])

        self._display_columns = list(desired_display)
        tree["displaycolumns"] = tuple(self._display_columns)

        for col in cols:
            tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
            if col == "raw_event":
                tree.column(col, width=1200, minwidth=300, stretch=True)
            else:
                tree.column(
                    col,
                    width=max(len(col) * 8, 80),
                    minwidth=60,
                    stretch=False,
                )
        # Inserción por lotes para no congelar la GUI
        self._tree_batch_rows = rows
        self._tree_batch_idx = 0
        self._insert_tree_batch()

    def _insert_tree_batch(self):
        """Inserta filas en el Treeview en lotes de 500 para mantener la GUI responsiva."""
        BATCH = 500
        tree = self._tree
        rows = self._tree_batch_rows
        start = self._tree_batch_idx
        end = min(start + BATCH, len(rows))
        for i in range(start, end):
            tree.insert("", "end", values=rows[i])
        self._tree_batch_idx = end
        if end < len(rows):
            pct = int(end * 100 / len(rows))
            self._set_global_progress(
                pct, f"Cargando tabla... {pct}% ({end:,}/{len(rows):,})"
            )
            self.root.after(1, self._insert_tree_batch)
        else:
            self._tree_batch_rows = None
            self._finish_global_progress(f"Tabla cargada · {len(rows):,} filas")

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
                        # Exacto: al menos una celda debe matchear
                        cmp_val = test_value[1:].strip()
                        if not any(
                            self._check_single_condition(f"={cmp_val}", str(v).lower())
                            for v in row
                        ):
                            ok = False
                            break
                    elif test_value.startswith("!"):
                        # Excluir: row_text NO debe contener
                        if not self._check_single_condition(test_value, row_text):
                            ok = False
                            break
                    else:
                        # Contiene / wildcard
                        if not self._check_single_condition(test_value, row_text):
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
            m.add_separator()
            m.add_command(
                label=f"Mover columna a la izquierda: {col_name}",
                command=lambda: self._move_result_column(col_name, -1),
            )
            m.add_command(
                label=f"Mover columna a la derecha: {col_name}",
                command=lambda: self._move_result_column(col_name, 1),
            )

        if m.index("end") is not None:
            m.tk_popup(event.x_root, event.y_root)

    def _results_filter_by(self, col_name: str, value: str):
        """Aplica filtro en la tabla de Resultados directamente."""
        self._results_filters.append({"field": col_name, "value": value})
        self._render_result_filter_chips()
        self._apply_filter()

    def _move_result_column(self, col_name: str, direction: int):
        """Reordena columnas visibles en Resultados."""
        if col_name not in self._display_columns:
            return
        idx = self._display_columns.index(col_name)
        new_idx = idx + direction
        if new_idx < 0 or new_idx >= len(self._display_columns):
            return
        self._display_columns[idx], self._display_columns[new_idx] = (
            self._display_columns[new_idx],
            self._display_columns[idx],
        )
        self._tree["displaycolumns"] = self._display_columns

    def _open_column_selector(self):
        """Selector para mostrar/ocultar columnas visibles en Resultados."""
        if not self._csv_columns:
            messagebox.showinfo("Sin datos", "Carga primero un CSV de resultados.")
            return

        popup = tk.Toplevel(self.root)
        popup.title("Columnas visibles")
        popup.transient(self.root)
        popup.resizable(False, False)

        body = ttk.Frame(popup, padding=8)
        body.pack(fill="both", expand=True)

        vars_map: dict[str, tk.BooleanVar] = {}
        for col in self._csv_columns:
            is_visible = (
                col in self._display_columns and col not in self._hidden_columns
            )
            var = tk.BooleanVar(value=is_visible)
            vars_map[col] = var
            ttk.Checkbutton(body, text=col, variable=var).pack(anchor="w")

        btns = ttk.Frame(popup, padding=(8, 0, 8, 8))
        btns.pack(fill="x")

        def show_all():
            for var in vars_map.values():
                var.set(True)

        def hide_all():
            for var in vars_map.values():
                var.set(False)

        def apply_changes():
            selected = [col for col, var in vars_map.items() if var.get()]
            if not selected:
                messagebox.showwarning(
                    "Selección inválida", "Debes dejar al menos una columna visible."
                )
                return

            selected_set = set(selected)
            self._hidden_columns = {
                col for col in self._csv_columns if col not in selected_set
            }
            ordered = [col for col in self._display_columns if col in selected_set]
            ordered += [
                col
                for col in self._csv_columns
                if col in selected_set and col not in ordered
            ]
            self._display_columns = ordered
            self._tree["displaycolumns"] = tuple(self._display_columns)
            popup.destroy()

        ttk.Button(btns, text="Mostrar todo", command=show_all).pack(side="left")
        ttk.Button(btns, text="Ocultar todo", command=hide_all).pack(
            side="left", padx=4
        )
        ttk.Button(btns, text="Cancelar", command=popup.destroy).pack(side="right")
        ttk.Button(btns, text="Aplicar", command=apply_changes).pack(
            side="right", padx=4
        )

        popup.grab_set()

    def _on_tree_left_press(self, event):
        if self._tree.identify_region(event.x, event.y) != "heading":
            self._header_drag_col = ""
            self._header_drag_active = False
            return

        col_id = self._tree.identify_column(event.x)
        try:
            col_idx = int(col_id.lstrip("#")) - 1
        except ValueError:
            self._header_drag_col = ""
            self._header_drag_active = False
            return

        display_cols = list(self._tree["displaycolumns"])
        if col_idx < 0 or col_idx >= len(display_cols):
            self._header_drag_col = ""
            self._header_drag_active = False
            return

        self._header_drag_col = display_cols[col_idx]
        self._header_drag_start_x = event.x
        self._header_drag_active = False

    def _on_tree_left_drag(self, event):
        if not self._header_drag_col:
            return
        if abs(event.x - self._header_drag_start_x) >= 12:
            self._header_drag_active = True

    def _on_tree_left_release(self, event):
        if not self._header_drag_col:
            return

        try:
            if self._header_drag_active:
                target_col_id = self._tree.identify_column(event.x)
                target_idx = int(target_col_id.lstrip("#")) - 1
                display_cols = list(self._tree["displaycolumns"])
                if not display_cols:
                    return
                target_idx = max(0, min(target_idx, len(display_cols) - 1))
                src_idx = display_cols.index(self._header_drag_col)
                if src_idx != target_idx:
                    moved_col = display_cols.pop(src_idx)
                    display_cols.insert(target_idx, moved_col)
                    self._display_columns = display_cols
                    self._tree["displaycolumns"] = tuple(display_cols)
                    self._suppress_sort_once = True
                    return "break"
        except (ValueError, tk.TclError):
            pass
        finally:
            self._header_drag_col = ""
            self._header_drag_active = False

        return None

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
        if self._suppress_sort_once:
            self._suppress_sort_once = False
            return
        if col not in self._csv_columns:
            return
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True

        if _HAS_PANDAS and self._df is not None:
            numeric = pd.to_numeric(self._df[col], errors="coerce")
            sort_col = (
                numeric.fillna(float("inf"))
                if self._sort_asc
                else numeric.fillna(float("-inf"))
            )
            if numeric.isna().all():
                self._df = self._df.sort_values(
                    by=col, ascending=self._sort_asc, key=lambda s: s.str.lower()
                )
            else:
                order = sort_col.argsort()
                if not self._sort_asc:
                    order = order[::-1]
                self._df = self._df.iloc[order].reset_index(drop=True)
            self._all_rows = self._df.values.tolist()
        else:
            idx = self._csv_columns.index(col)

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

        # ── Panel izquierdo: controles (con scroll) ─────────────────────────
        ctrl_outer = ttk.LabelFrame(paned, text="Configuración", padding=0)
        paned.add(ctrl_outer, weight=0)

        _canvas = tk.Canvas(ctrl_outer, highlightthickness=0, width=220)
        _vsb = ttk.Scrollbar(ctrl_outer, orient="vertical", command=_canvas.yview)
        _canvas.configure(yscrollcommand=_vsb.set)
        _vsb.pack(side="right", fill="y")
        _canvas.pack(side="left", fill="both", expand=True)

        ctrl = ttk.Frame(_canvas, padding=8)
        _canvas.create_window((0, 0), window=ctrl, anchor="nw")

        def _on_ctrl_configure(_event=None):
            _canvas.configure(scrollregion=_canvas.bbox("all"))

        ctrl.bind("<Configure>", _on_ctrl_configure)

        # Scroll con rueda del ratón en el panel de controles
        def _on_mousewheel(event):
            _canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_mousewheel(event):
            _canvas.bind_all("<MouseWheel>", _on_mousewheel)

        def _unbind_mousewheel(event):
            _canvas.unbind_all("<MouseWheel>")

        _canvas.bind("<Enter>", _bind_mousewheel)
        _canvas.bind("<Leave>", _unbind_mousewheel)

        ttk.Label(ctrl, text="Agrupar por:").pack(anchor="w")
        self._pivot_col_var = tk.StringVar(value="src_ip")
        self._pivot_col_cb = ttk.Combobox(
            ctrl,
            textvariable=self._pivot_col_var,
            values=_PIVOT_FIELDS,
            width=22,
        )
        self._pivot_col_cb.pack(fill="x", pady=(0, 8))
        self._pivot_col_cb.bind(
            "<<ComboboxSelected>>", lambda _: self._on_analysis_change()
        )

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
        self._pivot_secondary_col_cb.bind(
            "<<ComboboxSelected>>", lambda _: self._on_analysis_change()
        )

        ttk.Label(ctrl, text="Vendor: ").pack(anchor="w")
        self._analysis_vendor_var = tk.StringVar(value="(todos)")
        self._analysis_vendor_cb = ttk.Combobox(
            ctrl,
            textvariable=self._analysis_vendor_var,
            values=_ANALYSIS_VENDOR_OPTIONS,
            state="readonly",
            width=22,
        )
        self._analysis_vendor_cb.pack(fill="x", pady=(0, 8))
        self._analysis_vendor_cb.bind(
            "<<ComboboxSelected>>", lambda _: self._on_analysis_change()
        )

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
        self._pivot_metric_cb = ttk.Combobox(
            ctrl,
            textvariable=self._pivot_metric_var,
            values=_PIVOT_METRICS,
            state="readonly",
            width=22,
        )
        self._pivot_metric_cb.pack(fill="x", pady=(0, 8))
        self._pivot_metric_cb.bind(
            "<<ComboboxSelected>>", lambda _: self._on_analysis_change()
        )

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
        self._pivot_chart_cb = ttk.Combobox(
            ctrl,
            textvariable=self._pivot_chart_var,
            values=_CHART_TYPES,
            state="readonly",
            width=22,
        )
        self._pivot_chart_cb.pack(fill="x", pady=(0, 10))
        self._pivot_chart_cb.bind(
            "<<ComboboxSelected>>", lambda _: self._on_analysis_change()
        )

        ttk.Button(ctrl, text="🔄  Regenerar", command=self._generate_pivot).pack(
            fill="x"
        )
        self._analysis_zoom_back_btn = ttk.Button(
            ctrl,
            text="↩  Volver zoom",
            command=self._analysis_zoom_back,
            state="disabled",
        )
        self._analysis_zoom_back_btn.pack(fill="x", pady=(4, 0))
        ttk.Button(ctrl, text="⚡  Forzar refresco", command=self._generate_pivot).pack(
            fill="x", pady=(4, 0)
        )
        ttk.Button(
            ctrl, text="💾  Exportar (imagen + CSV)", command=self._export_chart
        ).pack(fill="x", pady=(4, 0))
        ttk.Button(
            ctrl, text="📋  Exportar detalle (filas)", command=self._export_detail_csv
        ).pack(fill="x", pady=(4, 0))
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
            text="(= exacto, ! excluye, AND, OR)",
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

        # ── Panel derecho: tabla + gráfico (separador arrastrable) ────────────
        right = tk.PanedWindow(
            paned, orient=tk.VERTICAL, sashwidth=6, sashrelief="raised",
            bg="#cccccc",
        )
        paned.add(right, weight=1)

        # Tabla pivot
        tbl_frame = ttk.LabelFrame(right, text="Tabla pivot", padding=4)
        right.add(tbl_frame, minsize=80, stretch="always")
        self._pivot_tree = ttk.Treeview(tbl_frame, show="headings", height=8)
        vsb_p = ttk.Scrollbar(
            tbl_frame, orient="vertical", command=self._pivot_tree.yview
        )
        self._pivot_tree.configure(yscrollcommand=vsb_p.set)
        self._pivot_tree.pack(side="left", fill="both", expand=True)
        vsb_p.pack(side="right", fill="y")
        self._pivot_tree.bind(
            "<Button-3>",
            lambda e: self._show_tree_copy_menu(e, self._pivot_tree),
        )

        # Área de gráfico
        chart_frame = ttk.LabelFrame(right, text="Gráfico", padding=4)
        right.add(chart_frame, minsize=120, stretch="always")

        if _HAS_MPL:
            self._fig = Figure(figsize=(8.8, 5.2), dpi=110, facecolor="#ffffff")
            self._canvas_mpl = FigureCanvasTkAgg(self._fig, master=chart_frame)
            self._canvas_mpl.get_tk_widget().pack(fill="both", expand=True)
            self._canvas_mpl.mpl_connect(
                "button_press_event", self._on_analysis_dblclick
            )
            self._canvas_mpl.mpl_connect(
                "button_press_event", self._on_analysis_rightclick
            )
        else:
            self._canvas_mpl = None
            ttk.Label(
                chart_frame,
                text="matplotlib no disponible.\nInstala con:  pip install matplotlib",
                justify="center",
                foreground="gray",
            ).pack(expand=True)

        # self._setup_analysis_auto_refresh()  # Desactivado: solo bajo demanda

    def _build_histograms_tab(self):
        tab = self._tab_histograms

        paned = ttk.PanedWindow(tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=8)

        ctrl_outer = ttk.LabelFrame(paned, text="Configuración temporal", padding=0)
        paned.add(ctrl_outer, weight=0)

        _hcanvas = tk.Canvas(ctrl_outer, highlightthickness=0, width=220)
        _hvsb = ttk.Scrollbar(ctrl_outer, orient="vertical", command=_hcanvas.yview)
        _hcanvas.configure(yscrollcommand=_hvsb.set)
        _hvsb.pack(side="right", fill="y")
        _hcanvas.pack(side="left", fill="both", expand=True)

        ctrl = ttk.Frame(_hcanvas, padding=8)
        _hcanvas.create_window((0, 0), window=ctrl, anchor="nw")

        def _on_hctrl_configure(_event=None):
            _hcanvas.configure(scrollregion=_hcanvas.bbox("all"))

        ctrl.bind("<Configure>", _on_hctrl_configure)

        def _on_hmousewheel(event):
            _hcanvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_hmousewheel(event):
            _hcanvas.bind_all("<MouseWheel>", _on_hmousewheel)

        def _unbind_hmousewheel(event):
            _hcanvas.unbind_all("<MouseWheel>")

        _hcanvas.bind("<Enter>", _bind_hmousewheel)
        _hcanvas.bind("<Leave>", _unbind_hmousewheel)

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
        hist_from_row = ttk.Frame(ctrl)
        hist_from_row.pack(fill="x", pady=(0, 4))
        ttk.Entry(hist_from_row, textvariable=self._hist_from_var).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            hist_from_row,
            text="📅",
            width=3,
            command=lambda: self._open_calendar_popup(self._hist_from_var),
        ).pack(side="left", padx=(4, 0))
        ttk.Label(ctrl, text="Hasta:").pack(anchor="w")
        self._hist_to_var = tk.StringVar()
        hist_to_row = ttk.Frame(ctrl)
        hist_to_row.pack(fill="x", pady=(0, 8))
        ttk.Entry(hist_to_row, textvariable=self._hist_to_var).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(
            hist_to_row,
            text="📅",
            width=3,
            command=lambda: self._open_calendar_popup(self._hist_to_var),
        ).pack(side="left", padx=(4, 0))
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
        self._hist_bucket_var = tk.StringVar(value="Día")
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
        ).pack(anchor="w", pady=(0, 2))
        self._hist_fill_gaps_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            ctrl, text="Rellenar intervalos vacíos", variable=self._hist_fill_gaps_var
        ).pack(anchor="w", pady=(0, 2))
        self._hist_ioc_only_var = tk.BooleanVar()
        ttk.Checkbutton(
            ctrl, text="Solo IOC hits", variable=self._hist_ioc_only_var
        ).pack(anchor="w", pady=(0, 8))

        self._hist_generate_btn = ttk.Button(
            ctrl, text="📊  Generar histograma", command=self._generate_histogram_view
        )
        self._hist_generate_btn.pack(fill="x")
        self._hist_zoom_back_btn = ttk.Button(
            ctrl,
            text="↩  Volver zoom",
            command=self._hist_zoom_back,
            state="disabled",
        )
        self._hist_zoom_back_btn.pack(fill="x", pady=(4, 0))
        ttk.Button(
            ctrl, text="⚡  Forzar refresco", command=self._generate_histogram_view
        ).pack(fill="x", pady=(4, 0))
        ttk.Button(
            ctrl, text="💾  Exportar (imagen + CSV)", command=self._export_hist_chart
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
        self._hist_tree.bind(
            "<Button-3>",
            lambda e: self._show_tree_copy_menu(e, self._hist_tree),
        )

        chart_frame = ttk.LabelFrame(right, text="Histograma", padding=4)
        right.add(chart_frame, weight=2)
        if _HAS_MPL:
            self._hist_fig = Figure(figsize=(8.8, 5.2), dpi=110, facecolor="#ffffff")
            self._hist_canvas_mpl = FigureCanvasTkAgg(
                self._hist_fig, master=chart_frame
            )
            self._hist_canvas_mpl.get_tk_widget().pack(fill="both", expand=True)
            self._hist_canvas_mpl.mpl_connect(
                "button_press_event", self._on_hist_dblclick
            )
            self._hist_canvas_mpl.mpl_connect(
                "button_press_event", self._on_hist_rightclick
            )
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

        # self._setup_hist_auto_refresh()  # Desactivado: solo bajo demanda

    def _setup_analysis_auto_refresh(self):
        tracked_vars = [
            self._pivot_col_var,
            self._pivot_secondary_col_var,
            self._analysis_vendor_var,
            self._analysis_from_var,
            self._analysis_to_var,
            self._analysis_filter1_field_var,
            self._analysis_filter1_value_var,
            self._analysis_filter2_field_var,
            self._analysis_filter2_value_var,
            self._analysis_exclude_empty_var,
            self._pivot_metric_var,
            self._pivot_topn_var,
            self._pivot_topn_all,
            self._pivot_ioc_only_var,
            self._pivot_chart_var,
        ]
        for var in tracked_vars:
            var.trace_add("write", lambda *_: self._on_analysis_change())

    def _setup_hist_auto_refresh(self):
        tracked_vars = [
            self._hist_series_col_var,
            self._hist_vendor_var,
            self._hist_from_var,
            self._hist_to_var,
            self._hist_filter1_field_var,
            self._hist_filter1_value_var,
            self._hist_filter2_field_var,
            self._hist_filter2_value_var,
            self._hist_bucket_var,
            self._hist_metric_var,
            self._hist_topn_var,
            self._hist_topn_all,
            self._hist_exclude_empty_var,
            self._hist_fill_gaps_var,
            self._hist_ioc_only_var,
        ]
        for var in tracked_vars:
            var.trace_add("write", lambda *_: self._on_hist_change())

    def _on_analysis_change(self):
        """Auto-generate pivot cuando cambian los controles."""
        if self._analysis_refresh_after_id is not None:
            self.root.after_cancel(self._analysis_refresh_after_id)

        def _refresh():
            self._analysis_refresh_after_id = None
            if self._nb.select() != str(self._tab_analysis):
                return
            if not self._all_rows or not self._csv_columns:
                return
            from_value = self._analysis_from_var.get().strip()
            to_value = self._analysis_to_var.get().strip()
            if from_value and self._parse_time_bound(from_value) is None:
                return
            if to_value and self._parse_time_bound(to_value, is_end=True) is None:
                return
            self._generate_pivot()

        self._analysis_refresh_after_id = self.root.after(250, _refresh)

    def _on_hist_change(self):
        """Auto-generate histogram cuando cambian los controles temporales."""
        if self._hist_refresh_after_id is not None:
            self.root.after_cancel(self._hist_refresh_after_id)

        def _refresh():
            self._hist_refresh_after_id = None
            if self._nb.select() != str(self._tab_histograms):
                return
            if not self._all_rows or not self._csv_columns:
                return
            if "timestamp" not in self._csv_columns:
                return
            if self._hist_generate_btn.cget("state") == "disabled":
                return
            from_value = self._hist_from_var.get().strip()
            to_value = self._hist_to_var.get().strip()
            if from_value and self._parse_time_bound(from_value) is None:
                return
            if to_value and self._parse_time_bound(to_value, is_end=True) is None:
                return
            self._generate_histogram_view()

        self._hist_refresh_after_id = self.root.after(300, _refresh)

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
        cell_value = self._get_row_value(row, field_name).lower()

        # Detectar OR (case-insensitive)
        or_parts = re.split(r"\s+OR\s+", raw_value, flags=re.IGNORECASE)
        if len(or_parts) > 1:
            for part in or_parts:
                and_parts = re.split(r"\s+AND\s+", part.strip(), flags=re.IGNORECASE)
                if all(
                    self._check_single_condition(c.strip(), cell_value)
                    for c in and_parts
                ):
                    return True
            return False

        # Detectar AND (case-insensitive)
        and_parts = re.split(r"\s+AND\s+", raw_value, flags=re.IGNORECASE)
        if len(and_parts) > 1:
            return all(
                self._check_single_condition(c.strip(), cell_value) for c in and_parts
            )

        return self._check_single_condition(raw_value, cell_value)

    def _check_single_condition(self, raw_value: str, cell_value: str) -> bool:
        """Evalúa una condición simple (sin OR). Soporta *, ! y =."""
        from fnmatch import fnmatch

        exact = raw_value.startswith("=")
        exclude = raw_value.startswith("!")
        cmp_value = raw_value[1:].strip() if (exact or exclude) else raw_value
        cmp_value = cmp_value.lower()

        has_wildcard = "*" in cmp_value or "?" in cmp_value

        if exact:
            if has_wildcard:
                return fnmatch(cell_value, cmp_value)
            return cell_value == cmp_value
        if exclude:
            if has_wildcard:
                return not fnmatch(cell_value, cmp_value)
            return cmp_value not in cell_value
        # Contiene (default) — con wildcard usa fnmatch
        if has_wildcard:
            return fnmatch(cell_value, cmp_value)
        return cmp_value in cell_value

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
        self._set_global_progress(0, "Generando gráfico de análisis... 0%")
        if not self._all_rows or not self._csv_columns:
            self._finish_global_progress("Sin datos para análisis.")
            messagebox.showwarning(
                "Sin datos",
                "Carga primero un CSV en la pestaña Resultados o desde allí.",
            )
            return

        col = self._pivot_col_var.get().strip()
        if not self._field_exists_for_analysis(col):
            self._finish_global_progress("Error: campo de análisis no disponible.")
            messagebox.showerror(
                "Error", f"Columna '{col}' no encontrada en los datos."
            )
            return

        secondary_col = self._pivot_secondary_col_var.get().strip()
        use_secondary = secondary_col and secondary_col != _NO_SECONDARY_FIELD
        if use_secondary and not self._field_exists_for_analysis(secondary_col):
            self._finish_global_progress("Error: campo secundario no disponible.")
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
        total_rows = max(1, len(rows))
        for idx, row in enumerate(rows, 1):
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
            if idx % 2000 == 0:
                pct = min(90, int((idx * 90) / total_rows))
                self._set_global_progress(
                    pct, f"Generando gráfico de análisis... {pct}%"
                )
                self.root.update_idletasks()

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

        # Guardar datos para exportación
        self._last_pivot_labels = labels
        self._last_pivot_values = values
        self._last_pivot_meta = {
            "col": col,
            "secondary_col": secondary_col if use_secondary else None,
            "metric": metric_label,
            "subtitle": _subtitle,
            "ioc_only": self._pivot_ioc_only_var.get(),
            "vendor_filter": self._analysis_vendor_var.get().strip(),
            "from_value": self._analysis_from_var.get().strip(),
            "to_value": self._analysis_to_var.get().strip(),
            "stacked": False,
        }

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

        # Si todos los labels comparten el mismo primario/secundario, simplificar
        _chart_label_field = None  # qué campo representan los labels del gráfico
        if secondary_idx is not None and chart_labels:
            primaries = {lbl[0] for lbl in labels}
            secondaries = {lbl[1] for lbl in labels}
            if len(primaries) == 1:
                # Todos misma red → mostrar solo el campo secundario
                chart_labels = [lbl[1] for lbl in labels]
                _chart_label_field = secondary_col
            elif len(secondaries) == 1:
                # Todos misma acción → mostrar solo el primario
                chart_labels = [lbl[0] for lbl in labels]
                _chart_label_field = col
        if _chart_label_field is None:
            _chart_label_field = col
        self._last_chart_label_field = _chart_label_field
        self._last_chart_labels = list(chart_labels)

        # ── Dibujar gráfico ───────────────────────────────────────────────────
        if self._canvas_mpl is not None:
            _chart_type = self._pivot_chart_var.get()
            _NEEDS_MATRIX = {
                "Barras apiladas (H)",
                "Barras apiladas (V)",
                "Heatmap",
                "Radar",
                "Sunburst",
            }

            if _chart_type in _NEEDS_MATRIX and secondary_idx is not None:
                # Construir matriz: primary → {secondary → value}
                primary_totals: dict[str, float] = defaultdict(float)
                sec_totals: dict[str, float] = defaultdict(float)
                for (pv, sv), val in agg.items():
                    primary_totals[pv] += val
                    sec_totals[sv] += val
                # Ordenar primarios por total descendente
                sorted_primaries = sorted(
                    primary_totals.items(), key=lambda x: x[1], reverse=True
                )
                if not self._pivot_topn_all.get():
                    try:
                        topn = int(self._pivot_topn_var.get())
                    except ValueError:
                        topn = 15
                    sorted_primaries = sorted_primaries[:topn]
                stacked_primary_labels = [p[0] for p in sorted_primaries]

                # Secundarios ordenados por total descendente
                sorted_secs = sorted(
                    sec_totals.items(), key=lambda x: x[1], reverse=True
                )
                stacked_secondary_labels = [s[0] for s in sorted_secs]

                # Construir matriz
                stacked_matrix: dict[str, list[float]] = {}
                for s_name in stacked_secondary_labels:
                    stacked_matrix[s_name] = [
                        agg.get((p, s_name), 0.0) for p in stacked_primary_labels
                    ]

                # Guardar datos para exportación
                self._last_pivot_meta["stacked"] = True
                self._last_pivot_meta["stacked_primary"] = stacked_primary_labels
                self._last_pivot_meta["stacked_secondary"] = stacked_secondary_labels
                self._last_pivot_meta["stacked_matrix"] = stacked_matrix

                if _chart_type in ("Barras apiladas (H)", "Barras apiladas (V)"):
                    self._draw_stacked_chart(
                        stacked_primary_labels,
                        stacked_secondary_labels,
                        stacked_matrix,
                        col,
                        secondary_col,
                        metric_label,
                        _chart_type,
                        subtitle=_subtitle,
                    )
                elif _chart_type == "Heatmap":
                    self._draw_heatmap(
                        stacked_primary_labels,
                        stacked_secondary_labels,
                        stacked_matrix,
                        col,
                        secondary_col,
                        metric_label,
                        subtitle=_subtitle,
                    )
                elif _chart_type == "Radar":
                    self._draw_radar(
                        stacked_primary_labels,
                        stacked_secondary_labels,
                        stacked_matrix,
                        col,
                        secondary_col,
                        metric_label,
                        subtitle=_subtitle,
                    )
                elif _chart_type == "Sunburst":
                    self._draw_sunburst(
                        stacked_primary_labels,
                        stacked_secondary_labels,
                        stacked_matrix,
                        col,
                        secondary_col,
                        metric_label,
                        subtitle=_subtitle,
                    )
            elif _chart_type in _NEEDS_MATRIX and secondary_idx is None:
                messagebox.showinfo(
                    "Necesitas desglosar",
                    f"El gráfico '{_chart_type}' necesita un campo en 'Desglosar por'.\n"
                    "Selecciona un campo secundario y regenera.",
                )
            elif _chart_type == "Treemap":
                chart_title = (
                    col if secondary_idx is None else f"{col} / {secondary_col}"
                )
                self._draw_treemap(
                    chart_labels,
                    values,
                    chart_title,
                    metric_label,
                    subtitle=_subtitle,
                )
            else:
                chart_title = (
                    col if secondary_idx is None else f"{col} / {secondary_col}"
                )
                self._draw_chart(
                    chart_labels,
                    values,
                    chart_title,
                    metric_label,
                    _chart_type,
                    subtitle=_subtitle,
                )

        self._nb.select(self._tab_analysis)
        self._finish_global_progress("Gráfico de análisis listo (100%).")

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
            import math

            wedge = {"edgecolor": "white", "linewidth": 1.2}
            wedges, autotexts = ax.pie(
                values,
                autopct=None,
                colors=colors,
                wedgeprops=wedge,
                startangle=90,
            )
            for i, (w, label) in enumerate(zip(wedges, pretty_labels)):
                pct = values[i] / total * 100
                ang = (w.theta2 + w.theta1) / 2
                x = math.cos(math.radians(ang))
                y = math.sin(math.radians(ang))
                ha = "left" if x >= 0 else "right"
                conn_style = "arc3,rad=0.15" if x >= 0 else "arc3,rad=-0.15"
                ax.annotate(
                    f"{label}  ({pct:.1f}%)",
                    xy=(0.9 * x, 0.9 * y),
                    xytext=(1.35 * x, 1.25 * y),
                    ha=ha,
                    va="center",
                    fontsize=7,
                    arrowprops=dict(
                        arrowstyle="-",
                        color="#666666",
                        connectionstyle=conn_style,
                        lw=0.8,
                    ),
                )

        elif chart_type == "Donut":
            import math

            wedge = {"width": 0.42, "edgecolor": "white", "linewidth": 1.2}
            wedges, autotexts = ax.pie(
                values,
                autopct=None,
                colors=colors,
                wedgeprops=wedge,
                startangle=90,
            )
            for i, (w, label) in enumerate(zip(wedges, pretty_labels)):
                pct = values[i] / total * 100
                ang = (w.theta2 + w.theta1) / 2
                x = math.cos(math.radians(ang))
                y = math.sin(math.radians(ang))
                ha = "left" if x >= 0 else "right"
                conn_style = "arc3,rad=0.15" if x >= 0 else "arc3,rad=-0.15"
                ax.annotate(
                    f"{label}  ({pct:.1f}%)",
                    xy=(0.85 * x, 0.85 * y),
                    xytext=(1.35 * x, 1.25 * y),
                    ha=ha,
                    va="center",
                    fontsize=7,
                    arrowprops=dict(
                        arrowstyle="-",
                        color="#666666",
                        connectionstyle=conn_style,
                        lw=0.8,
                    ),
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
        self._analysis_zoom_stack.clear()
        if hasattr(self, "_analysis_zoom_back_btn"):
            self._analysis_zoom_back_btn.configure(state="disabled")

    def _draw_stacked_chart(
        self,
        primary_labels: list[str],
        secondary_labels: list[str],
        matrix: dict[str, list[float]],
        col: str,
        secondary_col: str,
        metric: str,
        chart_type: str,
        subtitle: str = "",
    ):
        """Barras apiladas: primary = cada barra, secondary = segmentos de color."""
        self._fig.clear()
        ax = self._fig.add_subplot(111)
        n = len(primary_labels)
        pretty_primary = [_truncate_label(l, 34) for l in primary_labels]
        colors = (_CHART_COLORS * ((len(secondary_labels) // len(_CHART_COLORS)) + 1))[
            : len(secondary_labels)
        ]

        horizontal = chart_type == "Barras apiladas (H)"

        if horizontal:
            positions = list(range(n))
            lefts = [0.0] * n
            for s_idx, s_name in enumerate(secondary_labels):
                vals = matrix[s_name]
                ax.barh(
                    positions,
                    vals,
                    left=lefts,
                    color=colors[s_idx],
                    label=s_name,
                    height=0.78,
                )
                lefts = [l + v for l, v in zip(lefts, vals)]
            self._style_axis(ax, value_axis="x")
            ax.set_yticks(positions)
            ax.set_yticklabels(pretty_primary, fontsize=8)
            ax.invert_yaxis()
            ax.set_xlabel(metric, fontsize=9)
            # Totales al final de cada barra
            for i, tot in enumerate(lefts):
                ax.text(
                    tot, i, f"  {tot:,.0f}", va="center", fontsize=7, color="#333333"
                )
        else:  # vertical
            positions = list(range(n))
            bottoms = [0.0] * n
            for s_idx, s_name in enumerate(secondary_labels):
                vals = matrix[s_name]
                ax.bar(
                    positions,
                    vals,
                    bottom=bottoms,
                    color=colors[s_idx],
                    label=s_name,
                    width=0.78,
                )
                bottoms = [b + v for b, v in zip(bottoms, vals)]
            self._style_axis(ax, value_axis="y")
            ax.set_xticks(positions)
            ax.set_xticklabels(pretty_primary, rotation=38, ha="right", fontsize=8)
            ax.set_ylabel(metric, fontsize=9)
            for i, tot in enumerate(bottoms):
                ax.text(
                    i,
                    tot,
                    f"{tot:,.0f}",
                    ha="center",
                    va="bottom",
                    fontsize=7,
                    color="#333333",
                )

        leg = ax.legend(fontsize=7, loc="best", framealpha=0.85)
        leg.set_draggable(True)

        title = f"{col}  por  {secondary_col}  —  {metric}"
        if subtitle:
            ax.set_title(f"{title}\n{subtitle}", fontsize=10, pad=8, color="#222222")
        else:
            ax.set_title(title, fontsize=11, pad=10, color="#222222")
        self._fig.tight_layout()
        self._canvas_mpl.draw()
        self._analysis_zoom_stack.clear()
        if hasattr(self, "_analysis_zoom_back_btn"):
            self._analysis_zoom_back_btn.configure(state="disabled")

    def _draw_heatmap(
        self,
        primary_labels: list[str],
        secondary_labels: list[str],
        matrix: dict[str, list[float]],
        col: str,
        secondary_col: str,
        metric: str,
        subtitle: str = "",
    ):
        """Mapa de calor: filas = primario, columnas = secundario, color = valor."""
        import numpy as np

        self._fig.clear()
        ax = self._fig.add_subplot(111)
        n_rows = len(primary_labels)
        n_cols = len(secondary_labels)
        data = np.zeros((n_rows, n_cols))
        for c_idx, s_name in enumerate(secondary_labels):
            vals = matrix.get(s_name, [0.0] * n_rows)
            for r_idx in range(n_rows):
                data[r_idx, c_idx] = vals[r_idx] if r_idx < len(vals) else 0.0

        im = ax.imshow(data, aspect="auto", cmap="YlOrRd", interpolation="nearest")
        self._fig.colorbar(im, ax=ax, label=metric, shrink=0.8)

        ax.set_xticks(range(n_cols))
        ax.set_xticklabels(
            [_truncate_label(s, 18) for s in secondary_labels],
            rotation=45,
            ha="right",
            fontsize=7,
        )
        ax.set_yticks(range(n_rows))
        ax.set_yticklabels(
            [_truncate_label(p, 30) for p in primary_labels],
            fontsize=7,
        )

        # Anotar valores en celdas (si no son demasiadas)
        if n_rows * n_cols <= 400:
            for r in range(n_rows):
                for c in range(n_cols):
                    v = data[r, c]
                    if v > 0:
                        txt_color = "white" if v > data.max() * 0.6 else "#222222"
                        ax.text(
                            c,
                            r,
                            f"{v:,.0f}",
                            ha="center",
                            va="center",
                            fontsize=6,
                            color=txt_color,
                        )

        title = f"{col}  ×  {secondary_col}  —  {metric}"
        if subtitle:
            ax.set_title(f"{title}\n{subtitle}", fontsize=10, pad=8, color="#222222")
        else:
            ax.set_title(title, fontsize=11, pad=10, color="#222222")
        self._fig.tight_layout()
        self._canvas_mpl.draw()
        self._analysis_zoom_stack.clear()
        if hasattr(self, "_analysis_zoom_back_btn"):
            self._analysis_zoom_back_btn.configure(state="disabled")

    def _draw_radar(
        self,
        primary_labels: list[str],
        secondary_labels: list[str],
        matrix: dict[str, list[float]],
        col: str,
        secondary_col: str,
        metric: str,
        subtitle: str = "",
    ):
        """Radar / araña: cada primario es una línea, ejes = secundarios."""
        import numpy as np

        self._fig.clear()
        n_axes = len(secondary_labels)
        if n_axes < 3:
            messagebox.showwarning(
                "Pocos ejes",
                "El gráfico Radar necesita al menos 3 valores en el campo desglosar.",
            )
            return
        # Limitar primarios para legibilidad
        max_series = 8
        if len(primary_labels) > max_series:
            primary_labels = primary_labels[:max_series]

        angles = np.linspace(0, 2 * np.pi, n_axes, endpoint=False).tolist()
        angles += angles[:1]  # cerrar polígono

        ax = self._fig.add_subplot(111, polar=True)
        colors = (_CHART_COLORS * ((len(primary_labels) // len(_CHART_COLORS)) + 1))[
            : len(primary_labels)
        ]

        for p_idx, p_name in enumerate(primary_labels):
            vals = [
                matrix.get(s, [0.0] * len(primary_labels))[p_idx]
                for s in secondary_labels
            ]
            vals += vals[:1]  # cerrar
            ax.plot(
                angles,
                vals,
                "o-",
                linewidth=1.5,
                label=_truncate_label(p_name, 24),
                color=colors[p_idx],
                markersize=3,
            )
            ax.fill(angles, vals, alpha=0.08, color=colors[p_idx])

        ax.set_thetagrids(
            [a * 180 / np.pi for a in angles[:-1]],
            [_truncate_label(s, 16) for s in secondary_labels],
            fontsize=7,
        )
        ax.tick_params(axis="y", labelsize=6)

        leg = ax.legend(
            fontsize=7, loc="upper right", bbox_to_anchor=(1.3, 1.1), framealpha=0.85
        )
        leg.set_draggable(True)

        title = f"{col}  por  {secondary_col}  —  {metric}"
        if subtitle:
            ax.set_title(f"{title}\n{subtitle}", fontsize=10, pad=18, color="#222222")
        else:
            ax.set_title(title, fontsize=11, pad=18, color="#222222")
        self._fig.tight_layout()
        self._canvas_mpl.draw()
        self._analysis_zoom_stack.clear()
        if hasattr(self, "_analysis_zoom_back_btn"):
            self._analysis_zoom_back_btn.configure(state="disabled")

    def _draw_sunburst(
        self,
        primary_labels: list[str],
        secondary_labels: list[str],
        matrix: dict[str, list[float]],
        col: str,
        secondary_col: str,
        metric: str,
        subtitle: str = "",
    ):
        """Sunburst: anillo interior = primario, anillo exterior = secundario."""
        import math

        self._fig.clear()
        ax = self._fig.add_subplot(111)

        # Anillo interior: totales por primario
        primary_totals = []
        for p_idx, p_name in enumerate(primary_labels):
            total = sum(
                matrix.get(s, [0.0] * len(primary_labels))[p_idx]
                for s in secondary_labels
            )
            primary_totals.append(total)
        grand_total = sum(primary_totals) or 1
        n_pri = len(primary_labels)
        pri_colors = (_CHART_COLORS * ((n_pri // len(_CHART_COLORS)) + 1))[:n_pri]

        # Anillo exterior: cada (primario, secundario) como segmento
        outer_values = []
        outer_colors = []
        outer_labels_list = []
        for p_idx, p_name in enumerate(primary_labels):
            base_r, base_g, base_b = (
                int(pri_colors[p_idx][1:3], 16),
                int(pri_colors[p_idx][3:5], 16),
                int(pri_colors[p_idx][5:7], 16),
            )
            sec_vals = []
            for s_name in secondary_labels:
                v = matrix.get(s_name, [0.0] * len(primary_labels))[p_idx]
                if v > 0:
                    sec_vals.append((s_name, v))
            for s_i, (s_name, v) in enumerate(sec_vals):
                factor = 0.7 + 0.3 * (s_i / max(len(sec_vals), 1))
                shade = "#{:02x}{:02x}{:02x}".format(
                    min(255, int(base_r * factor + 255 * (1 - factor))),
                    min(255, int(base_g * factor + 255 * (1 - factor))),
                    min(255, int(base_b * factor + 255 * (1 - factor))),
                )
                outer_values.append(v)
                outer_colors.append(shade)
                outer_labels_list.append(f"{_truncate_label(s_name, 14)}")

        # Dibujar anillo interior
        wedges_inner, _ = ax.pie(
            primary_totals,
            colors=pri_colors,
            radius=0.7,
            wedgeprops={"width": 0.35, "edgecolor": "white", "linewidth": 1.2},
            startangle=90,
        )
        # Anotaciones interiores
        for i, (w, label) in enumerate(zip(wedges_inner, primary_labels)):
            pct = primary_totals[i] / grand_total * 100
            if pct < 2:
                continue
            ang = (w.theta2 + w.theta1) / 2
            x = 0.52 * math.cos(math.radians(ang))
            y = 0.52 * math.sin(math.radians(ang))
            ax.text(
                x,
                y,
                f"{_truncate_label(label, 16)}\n{pct:.0f}%",
                ha="center",
                va="center",
                fontsize=6,
                color="#222222",
            )

        # Dibujar anillo exterior
        if outer_values:
            wedges_outer, _ = ax.pie(
                outer_values,
                colors=outer_colors,
                radius=1.0,
                wedgeprops={"width": 0.28, "edgecolor": "white", "linewidth": 0.8},
                startangle=90,
            )
            # Anotaciones exteriores (solo las significativas)
            for i, w in enumerate(wedges_outer):
                pct = outer_values[i] / grand_total * 100
                if pct < 1.5:
                    continue
                ang = (w.theta2 + w.theta1) / 2
                x = math.cos(math.radians(ang))
                y = math.sin(math.radians(ang))
                ha = "left" if x >= 0 else "right"
                ax.annotate(
                    f"{outer_labels_list[i]} ({pct:.1f}%)",
                    xy=(0.88 * x, 0.88 * y),
                    xytext=(1.25 * x, 1.18 * y),
                    ha=ha,
                    va="center",
                    fontsize=6,
                    arrowprops=dict(
                        arrowstyle="-",
                        color="#999999",
                        lw=0.6,
                        connectionstyle="arc3,rad=0.1" if x >= 0 else "arc3,rad=-0.1",
                    ),
                )

        ax.set_aspect("equal")
        title = f"{col}  →  {secondary_col}  —  {metric}"
        if subtitle:
            ax.set_title(f"{title}\n{subtitle}", fontsize=10, pad=8, color="#222222")
        else:
            ax.set_title(title, fontsize=11, pad=10, color="#222222")
        self._fig.tight_layout()
        self._canvas_mpl.draw()
        self._analysis_zoom_stack.clear()
        if hasattr(self, "_analysis_zoom_back_btn"):
            self._analysis_zoom_back_btn.configure(state="disabled")

    def _draw_treemap(
        self,
        labels: list,
        values: list,
        col: str,
        metric: str,
        subtitle: str = "",
    ):
        """Treemap — requiere squarify (pip install squarify)."""
        try:
            import squarify
        except ImportError:
            messagebox.showwarning(
                "squarify no instalado",
                "Para usar Treemap necesitas:\n  pip install squarify",
            )
            return
        self._fig.clear()
        ax = self._fig.add_subplot(111)
        n = len(labels)
        colors = (_CHART_COLORS * ((n // len(_CHART_COLORS)) + 1))[:n]
        total = sum(values) or 1
        display_labels = [
            f"{_truncate_label(l, 28)}\n{v:,.0f} ({v / total * 100:.1f}%)"
            for l, v in zip(labels, values)
        ]
        squarify.plot(
            sizes=values,
            label=display_labels,
            color=colors,
            alpha=0.85,
            ax=ax,
            text_kwargs={"fontsize": 7, "color": "#222222"},
        )
        ax.axis("off")
        title = f"{col}  —  {metric}"
        if subtitle:
            ax.set_title(f"{title}\n{subtitle}", fontsize=10, pad=8, color="#222222")
        else:
            ax.set_title(title, fontsize=11, pad=10, color="#222222")
        self._fig.tight_layout()
        self._canvas_mpl.draw()
        self._analysis_zoom_stack.clear()
        if hasattr(self, "_analysis_zoom_back_btn"):
            self._analysis_zoom_back_btn.configure(state="disabled")

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
        leg = ax.legend(fontsize=8)
        leg.set_draggable(True)
        self._fig.tight_layout()
        self._canvas_mpl.draw()
        self._analysis_zoom_stack.clear()
        if hasattr(self, "_analysis_zoom_back_btn"):
            self._analysis_zoom_back_btn.configure(state="disabled")

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
        self._analysis_zoom_stack.clear()
        if hasattr(self, "_analysis_zoom_back_btn"):
            self._analysis_zoom_back_btn.configure(state="disabled")
        self._status_var.set(
            f"Histograma temporal: {parsed_rows:,} filas · {n} intervalos · {bucket}"
        )
        self._nb.select(self._tab_analysis)

    def _generate_histogram_view(self):
        if self._hist_generate_btn.cget("state") == "disabled":
            return
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

        # Capturar variables de tkinter antes de ceder el hilo principal
        exclude_empty = self._hist_exclude_empty_var.get()
        ioc_only = self._hist_ioc_only_var.get()
        fill_gaps = self._hist_fill_gaps_var.get()
        topn_all = self._hist_topn_all.get()
        try:
            topn = int(self._hist_topn_var.get())
        except ValueError:
            topn = 8

        # Snapshots de las listas de datos (solo lectura, seguro entre hilos)
        all_rows_snap = self._all_rows
        csv_columns_snap = self._csv_columns

        self._hist_generate_btn.configure(state="disabled")
        self._hist_status_var.set("Calculando histograma…")
        self._set_global_progress(0, "Generando histograma... 0%")
        self.root.update_idletasks()

        def _worker():
            try:
                rows = self._get_rows_with_filters(
                    all_rows_snap,
                    vendor_filter=vendor_filter,
                    filter1_field=filter1_field,
                    filter1_value=filter1_value,
                    filter2_field=filter2_field,
                    filter2_value=filter2_value,
                    ioc_only=ioc_only,
                    from_value=from_value,
                    to_value=to_value,
                )
                if not rows:

                    def _no_data():
                        messagebox.showwarning(
                            "Sin datos",
                            "No hay filas que cumplan los filtros seleccionados.",
                        )
                        self._hist_generate_btn.configure(state="normal")
                        self._hist_status_var.set("Sin datos.")

                    self.root.after(0, _no_data)
                    return

                timestamp_idx = csv_columns_snap.index("timestamp")
                grouped: dict = defaultdict(lambda: defaultdict(float))
                series_totals: Counter = Counter()
                parsed_rows = 0
                total_rows = max(1, len(rows))
                for idx, row in enumerate(rows, 1):
                    dt = _parse_timestamp(row[timestamp_idx])
                    if dt is None:
                        continue
                    bucket_dt = _floor_timestamp(dt, bucket)
                    if series_field == _NO_SERIES_FIELD:
                        series_value = "Total"
                    else:
                        series_value = (
                            self._get_row_value(row, series_field) or "(vacío)"
                        )
                        if exclude_empty and series_value == "(vacío)":
                            continue
                    value = 1 if metric_idx is None else _safe_float(row[metric_idx])
                    grouped[bucket_dt][series_value] += value
                    series_totals[series_value] += value
                    parsed_rows += 1
                    if idx % 2000 == 0:
                        pct = min(90, int((idx * 90) / total_rows))
                        self.root.after(
                            0,
                            lambda p=pct: self._set_global_progress(
                                p, f"Generando histograma... {p}%"
                            ),
                        )

                if not grouped:

                    def _no_ts():
                        messagebox.showwarning(
                            "Sin serie temporal",
                            "No hay timestamps válidos tras aplicar los filtros.",
                        )
                        self._hist_generate_btn.configure(state="normal")
                        self._hist_status_var.set("Sin timestamps válidos.")
                        self._finish_global_progress("Sin timestamps válidos.")

                    self.root.after(0, _no_ts)
                    return

                series_names = [name for name, _ in series_totals.most_common()]
                if series_field != _NO_SERIES_FIELD and not topn_all:
                    series_names = series_names[:topn]

                if not series_names:
                    series_names = ["Total"]

                ordered_buckets = sorted(grouped.keys())

                # Rellenar huecos temporales si está activado
                if fill_gaps and len(ordered_buckets) >= 2:
                    start, end = ordered_buckets[0], ordered_buckets[-1]
                    if bucket == "Hora":
                        step = timedelta(hours=1)
                    elif bucket == "Día":
                        step = timedelta(days=1)
                    elif bucket == "Semana":
                        step = timedelta(weeks=1)
                    else:  # Mes
                        step = None
                    if step is not None:
                        full_buckets = []
                        cur = start
                        while cur <= end:
                            full_buckets.append(cur)
                            cur += step
                        ordered_buckets = full_buckets
                    else:
                        # Meses: incrementar mes a mes
                        full_buckets = []
                        cur = start
                        while cur <= end:
                            full_buckets.append(cur)
                            y, m = cur.year, cur.month
                            m += 1
                            if m > 12:
                                m = 1
                                y += 1
                            cur = cur.replace(year=y, month=m)
                        ordered_buckets = full_buckets

                labels = [_format_bucket(b, bucket) for b in ordered_buckets]
                series_matrix = {
                    name: [grouped[b].get(name, 0.0) for b in ordered_buckets]
                    for name in series_names
                }

                result = {
                    "bucket": bucket,
                    "metric": metric,
                    "series_field": series_field,
                    "vendor_filter": vendor_filter,
                    "filter1_field": filter1_field,
                    "filter1_value": filter1_value,
                    "filter2_field": filter2_field,
                    "filter2_value": filter2_value,
                    "ioc_only": ioc_only,
                    "from_value": from_value,
                    "to_value": to_value,
                    "series_names": series_names,
                    "series_totals": series_totals,
                    "series_matrix": series_matrix,
                    "labels": labels,
                    "ordered_buckets": ordered_buckets,
                    "parsed_rows": parsed_rows,
                }
                self.root.after(0, lambda: self._finish_histogram_render(result))
            except Exception as exc:

                def _fail():
                    self._hist_generate_btn.configure(state="normal")
                    self._hist_status_var.set("Error al calcular histograma.")
                    self._finish_global_progress("Error al generar histograma.")
                    messagebox.showerror("Error en histograma", str(exc))

                self.root.after(0, _fail)

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_histogram_render(self, result: dict):
        self._last_hist_result = result  # Guardar para exportación
        bucket = result["bucket"]
        metric = result["metric"]
        series_field = result["series_field"]
        vendor_filter = result["vendor_filter"]
        filter1_field = result["filter1_field"]
        filter1_value = result["filter1_value"]
        filter2_field = result["filter2_field"]
        filter2_value = result["filter2_value"]
        ioc_only = result["ioc_only"]
        from_value = result["from_value"]
        to_value = result["to_value"]
        series_names = result["series_names"]
        series_totals = result["series_totals"]
        series_matrix = result["series_matrix"]
        labels = result["labels"]
        ordered_buckets = result["ordered_buckets"]
        parsed_rows = result["parsed_rows"]

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
                        label=name,
                    )
                    bottoms = [bottoms[i] + values[i] for i in range(len(values))]
                leg = ax.legend(fontsize=7, ncol=2, loc="upper left")
                leg.set_draggable(True)

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
                ioc_only=ioc_only,
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
            self._hist_zoom_stack.clear()
            if hasattr(self, "_hist_zoom_back_btn"):
                self._hist_zoom_back_btn.configure(state="disabled")

        self._hist_status_var.set(
            f"Histograma: {parsed_rows:,} filas válidas · {len(ordered_buckets)} intervalos · {len(series_names)} series"
        )
        self._hist_generate_btn.configure(state="normal")
        self._finish_global_progress("Histograma listo (100%).")
        self._nb.select(self._tab_histograms)

    def _zoom_axis(self, ax, x: float, y: float, zoom_factor: float = 0.5):
        x0, x1 = ax.get_xlim()
        y0, y1 = ax.get_ylim()
        width = (x1 - x0) * zoom_factor
        height = (y1 - y0) * zoom_factor
        if width <= 0 or height <= 0:
            return
        ax.set_xlim(x - (width / 2), x + (width / 2))
        ax.set_ylim(y - (height / 2), y + (height / 2))

    def _on_analysis_dblclick(self, event):
        if not getattr(event, "dblclick", False) or event.inaxes is None:
            return
        if event.xdata is None or event.ydata is None:
            return
        ax = event.inaxes
        self._analysis_zoom_stack.append((ax.get_xlim(), ax.get_ylim()))
        self._zoom_axis(ax, event.xdata, event.ydata, zoom_factor=0.5)
        self._analysis_zoom_back_btn.configure(state="normal")
        self._canvas_mpl.draw_idle()

    # ── Copiar imagen / datos al portapapeles ─────────────────────────────
    def _copy_figure_to_clipboard(self, fig):
        """Copia una Figure de matplotlib al portapapeles de Windows como BMP."""
        try:
            buf = io.BytesIO()
            fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
            buf.seek(0)
            # Usar PIL si está disponible
            from PIL import Image
            img = Image.open(buf)
            bmp_buf = io.BytesIO()
            img.convert("RGB").save(bmp_buf, format="BMP")
            bmp_data = bmp_buf.getvalue()[14:]  # skip BMP file header
            bmp_buf.close()
            buf.close()
            import ctypes
            CF_DIB = 8
            kernel32 = ctypes.windll.kernel32
            user32 = ctypes.windll.user32
            user32.OpenClipboard(0)
            user32.EmptyClipboard()
            h = kernel32.GlobalAlloc(0x0042, len(bmp_data))
            p = kernel32.GlobalLock(h)
            ctypes.memmove(p, bmp_data, len(bmp_data))
            kernel32.GlobalUnlock(h)
            user32.SetClipboardData(CF_DIB, h)
            user32.CloseClipboard()
            self._set_global_progress(100, "Imagen copiada al portapapeles.")
        except ImportError:
            messagebox.showwarning(
                "Pillow necesario",
                "Instala Pillow para copiar imágenes:\n  pip install Pillow",
            )
        except Exception as exc:
            messagebox.showerror("Error al copiar imagen", str(exc))

    def _copy_tree_to_clipboard(self, tree: ttk.Treeview):
        """Copia el contenido de un Treeview al portapapeles como texto tabular."""
        cols = tree["columns"]
        header_texts = [tree.heading(c, "text") for c in cols]
        lines = ["\t".join(header_texts)]
        for iid in tree.get_children():
            vals = tree.item(iid, "values")
            lines.append("\t".join(str(v) for v in vals))
        text = "\n".join(lines)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._set_global_progress(
            100, f"Tabla copiada ({len(lines) - 1} filas)."
        )

    def _on_analysis_rightclick(self, event):
        """Click derecho en gráfico → menú contextual."""
        if event.button != 3:
            return
        # Construir menú
        m = tk.Menu(self.root, tearoff=0)
        m.add_command(
            label="📋  Copiar imagen",
            command=lambda: self._copy_figure_to_clipboard(self._fig),
        )
        m.add_command(
            label="📋  Copiar tabla pivot",
            command=lambda: self._copy_tree_to_clipboard(self._pivot_tree),
        )

        # Drill-down solo si se clicó sobre una barra
        bar_idx = None
        if event.inaxes is not None:
            stored_labels = getattr(self, "_last_chart_labels", [])
            ax = event.inaxes
            for p in ax.patches:
                if p.contains(event)[0]:
                    y_ticks = [t.get_text() for t in ax.get_yticklabels()]
                    x_ticks = [t.get_text() for t in ax.get_xticklabels()]
                    if y_ticks and any(y_ticks):
                        bar_idx = int(round(p.get_y() + p.get_height() / 2))
                    elif x_ticks and any(x_ticks):
                        bar_idx = int(round(p.get_x() + p.get_width() / 2))
                    break
            if (
                bar_idx is not None
                and 0 <= bar_idx < len(stored_labels)
            ):
                clicked_label = stored_labels[bar_idx]
                filter_field = getattr(self, "_last_chart_label_field", None)
                if not filter_field:
                    meta = self._last_pivot_meta
                    filter_field = meta.get("secondary_col") or meta.get("col", "")
                if filter_field:
                    m.add_separator()
                    m.add_command(
                        label=f"🔍  Drill-down: {filter_field}={clicked_label}",
                        command=lambda f=filter_field, v=clicked_label: self._do_drilldown(f, v),
                    )

        # Posicionar menú en coordenadas de pantalla
        widget = self._canvas_mpl.get_tk_widget()
        x_screen = widget.winfo_rootx() + int(event.x)
        y_screen = widget.winfo_rooty() + widget.winfo_height() - int(event.y)
        m.tk_popup(x_screen, y_screen)

    def _do_drilldown(self, filter_field: str, clicked_label: str):
        """Aplica drill-down en Filtro 2."""
        filter_value = f"={clicked_label}"
        f2_field = self._analysis_filter2_field_var.get().strip()
        f2_value = self._analysis_filter2_value_var.get().strip()
        if not f2_value or f2_field == _NO_FILTER_FIELD:
            self._analysis_filter2_field_var.set(filter_field)
            self._analysis_filter2_value_var.set(filter_value)
        else:
            if messagebox.askyesno(
                "Filtro 2 ocupado",
                f"Filtro 2 ya tiene: {f2_field}={f2_value}\n\n"
                f"¿Reemplazar con {filter_field}={clicked_label}?",
            ):
                self._analysis_filter2_field_var.set(filter_field)
                self._analysis_filter2_value_var.set(filter_value)
            else:
                return
        self._generate_pivot()

    def _on_hist_dblclick(self, event):
        if not getattr(event, "dblclick", False) or event.inaxes is None:
            return
        if event.xdata is None or event.ydata is None:
            return
        ax = event.inaxes
        self._hist_zoom_stack.append((ax.get_xlim(), ax.get_ylim()))
        self._zoom_axis(ax, event.xdata, event.ydata, zoom_factor=0.5)
        self._hist_zoom_back_btn.configure(state="normal")
        self._hist_canvas_mpl.draw_idle()

    def _on_hist_rightclick(self, event):
        """Menú contextual en histograma: copiar imagen / tabla."""
        if event.button != 3:
            return
        m = tk.Menu(self.root, tearoff=0)
        m.add_command(
            label="📋  Copiar imagen",
            command=lambda: self._copy_figure_to_clipboard(self._hist_fig),
        )
        m.add_command(
            label="📋  Copiar tabla series",
            command=lambda: self._copy_tree_to_clipboard(self._hist_tree),
        )
        widget = self._hist_canvas_mpl.get_tk_widget()
        x_screen = widget.winfo_rootx() + int(event.x)
        y_screen = widget.winfo_rooty() + widget.winfo_height() - int(event.y)
        m.tk_popup(x_screen, y_screen)

    def _show_tree_copy_menu(self, event, tree: ttk.Treeview):
        """Menú contextual para copiar contenido de un Treeview."""
        m = tk.Menu(self.root, tearoff=0)
        m.add_command(
            label="📋  Copiar toda la tabla",
            command=lambda: self._copy_tree_to_clipboard(tree),
        )
        # Copiar celda seleccionada
        col_id = tree.identify_column(event.x)
        row_id = tree.identify_row(event.y)
        if row_id and col_id:
            try:
                col_idx = int(col_id.lstrip("#")) - 1
                cell_value = str(tree.item(row_id, "values")[col_idx])
                m.add_command(
                    label=f'📋  Copiar celda: "{cell_value[:40]}"',
                    command=lambda v=cell_value: (
                        self.root.clipboard_clear(),
                        self.root.clipboard_append(v),
                    ),
                )
            except (ValueError, IndexError):
                pass
        m.tk_popup(event.x_root, event.y_root)

    def _analysis_zoom_back(self):
        if not self._analysis_zoom_stack or self._canvas_mpl is None:
            return
        ax_list = self._fig.get_axes()
        if not ax_list:
            return
        xlim, ylim = self._analysis_zoom_stack.pop()
        ax_list[0].set_xlim(*xlim)
        ax_list[0].set_ylim(*ylim)
        if not self._analysis_zoom_stack:
            self._analysis_zoom_back_btn.configure(state="disabled")
        self._canvas_mpl.draw_idle()

    def _hist_zoom_back(self):
        if not self._hist_zoom_stack or self._hist_canvas_mpl is None:
            return
        ax_list = self._hist_fig.get_axes()
        if not ax_list:
            return
        xlim, ylim = self._hist_zoom_stack.pop()
        ax_list[0].set_xlim(*xlim)
        ax_list[0].set_ylim(*ylim)
        if not self._hist_zoom_stack:
            self._hist_zoom_back_btn.configure(state="disabled")
        self._hist_canvas_mpl.draw_idle()

    def _get_session_folder(self) -> str:
        """Devuelve (y crea si no existe) la carpeta de sesión para exportaciones."""
        if not self._session_folder:
            today = datetime.now().strftime("%Y%m%d")
            base = (
                os.path.dirname(self._loaded_csv_path)
                if self._loaded_csv_path
                else os.getcwd()
            )
            self._session_folder = os.path.join(base, f"MasterOfParser_{today}")
        os.makedirs(self._session_folder, exist_ok=True)
        return self._session_folder

    @staticmethod
    def _safe_filename(name: str) -> str:
        """Convierte un título en nombre de fichero seguro."""
        name = re.sub(r'[<>:"/\\|?*\n]', "_", name)
        name = re.sub(r"\s+", "_", name.strip())
        name = re.sub(r"_+", "_", name).strip("_")
        return name[:120] or "export"

    def _export_hist_chart(self):
        if not _HAS_MPL or self._hist_canvas_mpl is None:
            messagebox.showwarning("Sin gráfico", "Genera primero un histograma.")
            return
        if not self._hist_fig.get_axes():
            messagebox.showwarning("Sin gráfico", "Genera primero un histograma.")
            return
        try:
            result = self._last_hist_result
            bucket = result.get("bucket", "histograma")
            series_field = result.get("series_field", "")
            metric = result.get("metric", "")
            base_name = f"hist_{bucket}"
            if series_field and series_field != _NO_SERIES_FIELD:
                base_name += f"_{series_field}"
            base_name += f"_{metric}"
            # Añadir contexto de filtros al nombre
            if result.get("ioc_only"):
                base_name += "_IOC"
            vnd = result.get("vendor_filter", "")
            if vnd and vnd != "(todos)":
                base_name += f"_{vnd}"
            if result.get("from_value"):
                base_name += f"_desde{result['from_value']}"
            if result.get("to_value"):
                base_name += f"_hasta{result['to_value']}"
            base_name = self._safe_filename(base_name)
            timestamp = datetime.now().strftime("%H%M%S")
            base_name = f"{base_name}_{timestamp}"

            folder = os.path.join(self._get_session_folder(), "histogramas")
            os.makedirs(folder, exist_ok=True)

            # Imagen
            img_path = os.path.join(folder, f"{base_name}.png")
            self._hist_fig.savefig(img_path, dpi=150, bbox_inches="tight")

            # CSV con series (totales)
            csv_path = os.path.join(folder, f"{base_name}.csv")
            series_names = result.get("series_names", [])
            labels = result.get("labels", [])
            series_matrix = result.get("series_matrix", {})
            with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["periodo"] + series_names)
                for idx_b, label in enumerate(labels):
                    row = [label] + [
                        (
                            series_matrix.get(name, [0])[idx_b]
                            if idx_b < len(series_matrix.get(name, []))
                            else 0
                        )
                        for name in series_names
                    ]
                    writer.writerow(row)

            # CSV con porcentajes
            pct_csv_path = os.path.join(folder, f"{base_name}_pct.csv")
            with open(pct_csv_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["periodo"] + [f"{n} (%)" for n in series_names])
                for idx_b, label in enumerate(labels):
                    row_vals = [
                        (
                            series_matrix.get(name, [0])[idx_b]
                            if idx_b < len(series_matrix.get(name, []))
                            else 0
                        )
                        for name in series_names
                    ]
                    bucket_total = sum(row_vals) or 1
                    row = [label] + [f"{v / bucket_total * 100:.1f}" for v in row_vals]
                    writer.writerow(row)

            messagebox.showinfo(
                "Exportado",
                f"Histograma guardado en:\n{img_path}\n\n"
                f"Datos (totales):\n{csv_path}\n\n"
                f"Datos (%):\n{pct_csv_path}",
            )
        except Exception as exc:
            import traceback

            traceback.print_exc()
            messagebox.showerror(
                "Error al exportar histograma",
                f"{type(exc).__name__}: {exc}",
            )

    def _export_detail_csv(self):
        """Exporta TODAS las filas que matchean los filtros actuales de Análisis."""
        if not self._all_rows or not self._csv_columns:
            messagebox.showwarning("Sin datos", "Carga primero un CSV.")
            return
        try:
            rows = self._get_analysis_rows(self._all_rows)
            if not rows:
                messagebox.showinfo("Sin filas", "Los filtros actuales no devuelven filas.")
                return

            meta = self._last_pivot_meta
            col = meta.get("col", "detalle")
            secondary = meta.get("secondary_col")
            base_name = f"detalle_{col}"
            if secondary:
                base_name += f"_{secondary}"
            if meta.get("ioc_only"):
                base_name += "_IOC"
            vnd = meta.get("vendor_filter", "")
            if vnd and vnd != "(todos)":
                base_name += f"_{vnd}"
            if meta.get("from_value"):
                base_name += f"_desde{meta['from_value']}"
            if meta.get("to_value"):
                base_name += f"_hasta{meta['to_value']}"
            base_name = self._safe_filename(base_name)
            timestamp = datetime.now().strftime("%H%M%S")
            base_name = f"{base_name}_{timestamp}"

            folder = os.path.join(self._get_session_folder(), "graficas")
            os.makedirs(folder, exist_ok=True)
            csv_path = os.path.join(folder, f"{base_name}.csv")

            with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(self._csv_columns)
                for row in rows:
                    writer.writerow(row)

            messagebox.showinfo(
                "Detalle exportado",
                f"{len(rows):,} filas exportadas a:\n{csv_path}",
            )
        except Exception as exc:
            import traceback
            traceback.print_exc()
            messagebox.showerror(
                "Error al exportar detalle",
                f"{type(exc).__name__}: {exc}",
            )

    def _export_chart(self):
        if not _HAS_MPL or self._canvas_mpl is None:
            messagebox.showwarning("Sin gráfico", "Genera primero un gráfico.")
            return
        if not self._fig.get_axes():
            messagebox.showwarning("Sin gráfico", "Genera primero un gráfico.")
            return
        try:
            meta = self._last_pivot_meta
            col = meta.get("col", "grafico")
            secondary = meta.get("secondary_col")
            metric = meta.get("metric", "Recuento")
            base_name = f"{col}"
            if secondary:
                base_name += f"_{secondary}"
            base_name += f"_{metric}"
            # Añadir contexto de filtros al nombre
            if meta.get("ioc_only"):
                base_name += "_IOC"
            vnd = meta.get("vendor_filter", "")
            if vnd and vnd != "(todos)":
                base_name += f"_{vnd}"
            if meta.get("from_value"):
                base_name += f"_desde{meta['from_value']}"
            if meta.get("to_value"):
                base_name += f"_hasta{meta['to_value']}"
            base_name = self._safe_filename(base_name)
            timestamp = datetime.now().strftime("%H%M%S")
            base_name = f"{base_name}_{timestamp}"

            folder = os.path.join(self._get_session_folder(), "graficas")
            os.makedirs(folder, exist_ok=True)

            # Imagen
            img_path = os.path.join(folder, f"{base_name}.png")
            self._fig.savefig(img_path, dpi=150, bbox_inches="tight")

            # CSV con tabla pivot
            csv_path = os.path.join(folder, f"{base_name}.csv")
            if meta.get("stacked"):
                # Formato matriz: filas = primarios, columnas = secundarios
                s_pri = meta.get("stacked_primary", [])
                s_sec = meta.get("stacked_secondary", [])
                s_mat = meta.get("stacked_matrix", {})
                with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([col] + s_sec + ["TOTAL"])
                    for p_idx, p_name in enumerate(s_pri):
                        row_vals = [
                            s_mat.get(s, [0.0] * len(s_pri))[p_idx] for s in s_sec
                        ]
                        writer.writerow([p_name] + row_vals + [sum(row_vals)])
                # CSV porcentajes
                pct_csv_path = os.path.join(folder, f"{base_name}_pct.csv")
                with open(pct_csv_path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([col] + [f"{s} (%)" for s in s_sec])
                    for p_idx, p_name in enumerate(s_pri):
                        row_vals = [
                            s_mat.get(s, [0.0] * len(s_pri))[p_idx] for s in s_sec
                        ]
                        row_total = sum(row_vals) or 1
                        writer.writerow(
                            [p_name] + [f"{v / row_total * 100:.1f}" for v in row_vals]
                        )
                messagebox.showinfo(
                    "Exportado",
                    f"Gráfico guardado en:\n{img_path}\n\n"
                    f"Datos (totales):\n{csv_path}\n\n"
                    f"Datos (%):\n{pct_csv_path}",
                )
            else:
                labels = self._last_pivot_labels
                values = self._last_pivot_values
                total = sum(values) or 1
                with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
                    writer = csv.writer(f)
                    if secondary:
                        writer.writerow([col, secondary, metric, "% total"])
                        for lbl, val in zip(labels, values):
                            primary_v, secondary_v = (
                                lbl if isinstance(lbl, tuple) else (lbl, "")
                            )
                            writer.writerow(
                                [
                                    primary_v,
                                    secondary_v,
                                    val,
                                    f"{val / total * 100:.1f}%",
                                ]
                            )
                    else:
                        writer.writerow([col, metric, "% total"])
                        for lbl, val in zip(labels, values):
                            writer.writerow([lbl, val, f"{val / total * 100:.1f}%"])
                messagebox.showinfo(
                    "Exportado",
                    f"Gráfico guardado en:\n{img_path}\n\nDatos CSV:\n{csv_path}",
                )
        except Exception as exc:
            import traceback

            traceback.print_exc()
            messagebox.showerror(
                "Error al exportar gráfico",
                f"{type(exc).__name__}: {exc}",
            )


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
        "--no-ioc-src",
        action="store_true",
        help="No relacionar IOCs con src_ip (origen)",
    )
    parser.add_argument(
        "--no-ioc-dst",
        action="store_true",
        help="No relacionar IOCs con dest_ip (destino)",
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

    if args.ioc_csv and not os.path.isfile(args.ioc_csv):
        print(f"[!] --ioc-csv no encontrado: {args.ioc_csv}", file=sys.stderr)
    if args.osint_csv and not os.path.isfile(args.osint_csv):
        print(f"[!] --osint-csv no encontrado: {args.osint_csv}", file=sys.stderr)

    valid_ioc_csv = (
        args.ioc_csv if args.ioc_csv and os.path.isfile(args.ioc_csv) else None
    )
    valid_osint_csv = (
        args.osint_csv if args.osint_csv and os.path.isfile(args.osint_csv) else None
    )
    vt_map, osint_map, source_logs = load_ioc_sources(valid_ioc_csv, valid_osint_csv)
    for msg in source_logs:
        print(msg)

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

    ioc_raw_keys = _collect_ioc_row_keys(ioc_map)
    ioc_raw_output_columns = _build_ioc_raw_output_columns(ioc_raw_keys)
    has_vt_source = bool(vt_map)
    has_osint_source = bool(osint_map)

    # ── Fichero de salida (BOM UTF-8 para Excel) ──────────────────────────────
    ts = datetime.now().strftime("%Y%m%d-%H%M")
    output_file = args.output or f"{ts}_CIM_PARSED.csv"
    output_columns = _get_output_columns(
        args.raw_event,
        extra_columns=ioc_raw_output_columns,
        include_vt=has_vt_source,
        include_osint=has_osint_source,
    )

    # ── Contar líneas para progreso ───────────────────────────────────────────
    print(f"[+] Leyendo:   {args.log_file}")
    total_lines = sum(
        1 for _ in open(args.log_file, encoding="utf-8", errors="replace")
    )
    print(f"[+] Líneas:    {total_lines:,}")
    if args.raw_event:
        print("[+] raw_event: activado (salida más pesada)")
    print(f"[+] Forti src_zone: {args.forti_src_zone_mode}")
    print(f"[+] IOC src_ip: {not args.no_ioc_src}, dest_ip: {not args.no_ioc_dst}")

    # ── Detectar formato QRadar ──────────────────────────────────────────────
    qradar_result = detect_qradar_tsv(args.log_file)
    qradar_cols = None
    qradar_delim = ","
    if qradar_result:
        qradar_cols, qradar_delim = qradar_result
        print(
            f"[+] Formato:   QRadar ({len(qradar_cols)} columnas, delim='{qradar_delim}', Payload incluido)"
        )
        payload_idx = qradar_cols.index(_QRADAR_PAYLOAD_COL)
    else:
        print("[+] Formato:   raw syslog (una línea = un evento)")

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

        first_line_skipped = False
        for i, line in enumerate(fin, 1):
            # Progreso cada 5%
            pct = (i * 100) // total_lines
            if pct % 5 == 0 and pct != last_pct:
                print(f"    {pct:3d}%  ({i:,}/{total_lines:,})", end="\r")
                last_pct = pct

            line = line.strip()
            if not line:
                continue

            # QRadar TSV: saltar cabecera y extraer campos
            qradar_extra: dict = {}
            if qradar_cols:
                if not first_line_skipped:
                    first_line_skipped = True
                    continue  # saltar cabecera
                parts = _split_qradar_line(line, len(qradar_cols), qradar_delim)
                qradar_extra = _extract_qradar_fields(qradar_cols, parts)
                line = parts[payload_idx] if payload_idx < len(parts) else ""
                if not line:
                    skipped += 1
                    continue

            record = parse_line(line)
            if not record:
                skipped += 1
                continue

            record = unify_cim_record(record, args.forti_src_zone_mode)

            # Merge columnas QRadar (no sobreescriben campos del payload)
            if qradar_extra:
                for k, v in qradar_extra.items():
                    if v and not record.get(k):
                        record[k] = v

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

            # Enriquecimiento IOC según dirección
            if not args.no_ioc_src:
                record.update(
                    enrich_ioc_candidates(
                        [record.get("src_ip", ""), record.get("src_ip_nat", "")],
                        ioc_set,
                        ioc_map,
                        "src",
                        ioc_raw_keys,
                    )
                )
            if not args.no_ioc_dst:
                record.update(
                    enrich_ioc_candidates(
                        [record.get("dest_ip", ""), record.get("dest_ip_nat", "")],
                        ioc_set,
                        ioc_map,
                        "dst",
                        ioc_raw_keys,
                    )
                )

            src_hit = record.get("ioc_src") == "YES" if not args.no_ioc_src else False
            dst_hit = record.get("ioc_dst") == "YES" if not args.no_ioc_dst else False
            has_ioc = src_hit or dst_hit
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
