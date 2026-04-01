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
import re
import sys
import os
import argparse
import threading
import queue
from collections import defaultdict
from datetime import datetime

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
    "DestinationUser": "dest_user",
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
    "appcat": "url_category",
    # Acción / Regla
    "action": "action",
    "policyname": "rule",
    "sessionid": "session_id",
    # Tráfico
    "sentbyte": "bytes_out",
    "rcvdbyte": "bytes_in",
    "sentpkt": "packets_out",
    "rcvdpkt": "packets_in",
    "duration": "duration",
    # Endpoint info (muy útil en Fortinet)
    "osname": "src_os",
    "srcssid": "src_zone",
}

# Columnas CIM de salida (orden para Excel)
CIM_COLUMNS = [
    # ── Tiempo ─────────────────────────────────────────────────────────────
    "timestamp",
    # ── Dispositivo ────────────────────────────────────────────────────────
    "dvc",
    "dvc_serial",
    "vendor",
    "subtype",
    # ── Acción ─────────────────────────────────────────────────────────────
    "action",
    "action_source",
    "rule",
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
]

# Regex LEEF 2.0: captura vendor, product, version, eventid, delimiter y KV
_LEEF_RE = re.compile(
    r"LEEF:2\.0\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|[^|]*\|(.*)", re.DOTALL
)

# Regex Fortinet: extrae pares key=value (valores quoted o unquoted)
_FORTINET_KV_RE = re.compile(r'(\w+)=("(?:[^"]*)"|\S+)')


# ─────────────────────────────────────────────────────────────────────────────
# Parsing LEEF (PaloAlto)
# ─────────────────────────────────────────────────────────────────────────────
def parse_leef_line(line: str) -> dict | None:
    """Parsea una línea LEEF 2.0 (PaloAlto) y devuelve un dict CIM."""
    m = _LEEF_RE.search(line)
    if not m:
        return None

    vendor = m.group(1).strip()  # "Palo Alto Networks"
    action = m.group(4).strip()  # "allow" / "deny" / "drop" ...
    kv_part = m.group(5)  # "cat=TRAFFIC|devTime=...|src=..."

    record: dict = {"vendor": vendor, "action": action}

    for pair in kv_part.split("|"):
        if "=" in pair:
            key, _, val = pair.partition("=")
            cim_key = LEEF_TO_CIM.get(key.strip())
            if cim_key:
                record[cim_key] = val.strip()

    return record


# ─────────────────────────────────────────────────────────────────────────────
# Parsing Fortinet (syslog KV)
# ─────────────────────────────────────────────────────────────────────────────
def parse_fortinet_line(line: str) -> dict | None:
    """Parsea una línea de log Fortinet (space-separated key=value) → dict CIM."""
    kv: dict = {}
    for m in _FORTINET_KV_RE.finditer(line):
        key = m.group(1)
        val = m.group(2).strip('"')
        kv[key] = val

    # Solo procesamos tráfico
    if kv.get("type") not in ("traffic", None):
        return None
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

    return record


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher: auto-detecta formato por línea
# ─────────────────────────────────────────────────────────────────────────────
def parse_line(line: str) -> dict | None:
    """Detecta si la línea es LEEF (PaloAlto) o Fortinet y la parsea."""
    if "LEEF:2.0" in line:
        return parse_leef_line(line)
    if "srcip=" in line and "dstip=" in line:
        return parse_fortinet_line(line)
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
]


def _empty_ioc(prefix: str) -> dict:
    return {f"ioc_{prefix}{s}": "" for s in _IOC_SUFFIX}


def enrich_ioc(ip: str, ioc_set: set, ioc_map: dict, prefix: str) -> dict:
    """Devuelve campos de enriquecimiento IOC para una IP dada."""
    result = _empty_ioc(prefix)
    if not ip:
        return result

    in_list = ip in ioc_set
    row = ioc_map.get(ip)

    if in_list or row:
        result[f"ioc_{prefix}"] = "YES"
        if row:
            result[f"ioc_{prefix}_risk"] = row.get("risk_score", "")
            result[f"ioc_{prefix}_country"] = row.get("country", "")
            result[f"ioc_{prefix}_owner"] = row.get("owner", "")
            result[f"ioc_{prefix}_asn"] = row.get("asn_full", row.get("asn", ""))
            result[f"ioc_{prefix}_reputation"] = row.get("reputation", "")
            result[f"ioc_{prefix}_malicious"] = row.get("malicious", "")
            result[f"ioc_{prefix}_vendors"] = row.get("vendors_malicious", "")
            result[f"ioc_{prefix}_cluster"] = row.get("cluster_flag", "")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Constantes para la pestaña Análisis
# ─────────────────────────────────────────────────────────────────────────────
_PIVOT_FIELDS = [
    "src_ip", "src_zone", "src_country",
    "dest_ip", "dest_port", "dest_zone", "dest_country",
    "app", "action", "transport", "vendor",
    "rule", "user",
    "ioc_src_country", "ioc_dst_country",
    "ioc_src_risk", "ioc_dst_risk",
]
_PIVOT_METRICS = [
    "Recuento",
    "Suma bytes_total",
    "Suma bytes_out",
    "Suma bytes_in",
    "Suma packets_total",
]
_CHART_TYPES = [
    "Barras horizontales",
    "Barras verticales",
    "Quesito (pie)",
    "Línea",
]
_CHART_COLORS = [
    "#377eb8", "#e41a1c", "#4daf4a", "#984ea3", "#ff7f00",
    "#a65628", "#f781bf", "#999999", "#1b9e77", "#d95f02",
    "#7570b3", "#e7298a", "#66a61e", "#e6ab02", "#a6761d",
    "#666666", "#8dd3c7", "#fb8072", "#bebada", "#80b1d3",
]

# ─────────────────────────────────────────────────────────────────────────────
# GUI (tkinter) — se lanza cuando no hay argumentos en línea de comandos
# ─────────────────────────────────────────────────────────────────────────────
class MasterOfParserGUI:
    def __init__(self, root: "tk.Tk"):
        self.root = root
        root.title("MasterOfParser")
        root.geometry("960x680")
        root.resizable(True, True)

        self._queue: queue.Queue = queue.Queue()
        self._last_output: str = ""

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self._nb = nb

        self._tab_parser   = ttk.Frame(nb)
        self._tab_results  = ttk.Frame(nb)
        self._tab_analysis = ttk.Frame(nb)
        nb.add(self._tab_parser,   text="  Parser  ")
        nb.add(self._tab_results,  text="  Resultados  ")
        nb.add(self._tab_analysis, text="  Análisis  ")

        self._build_parser_tab()
        self._build_results_tab()
        self._build_analysis_tab()

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
        filter_entry.bind("<Return>", lambda _: self._apply_filter())
        ttk.Label(ctrl, text="en columna:").pack(side="left")
        self._filter_col_var = tk.StringVar(value="(todas)")
        self._filter_col_cb = ttk.Combobox(
            ctrl,
            textvariable=self._filter_col_var,
            state="readonly",
            width=20,
        )
        self._filter_col_cb.pack(side="left", padx=4)
        ttk.Button(ctrl, text="Filtrar", command=self._apply_filter).pack(side="left")
        ttk.Button(ctrl, text="Limpiar", command=self._clear_filter).pack(
            side="left", padx=4
        )

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

        # Barra de estado
        self._status_var = tk.StringVar(value="Sin datos cargados")
        ttk.Label(tab, textvariable=self._status_var, anchor="w").pack(
            fill="x", padx=8, pady=2
        )

        self._all_rows: list = []
        self._csv_columns: list = []
        self._sort_col: str = ""
        self._sort_asc: bool = True

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
        output_file = self._out_var.get().strip() or None
        ioc_only = self._ioconly_var.get()
        extract_ips = (
            self._extract_path_var.get().strip() if self._extract_var.get() else None
        )

        if ioc_csv and not os.path.isfile(ioc_csv):
            messagebox.showerror("Error", f"IOC CSV no encontrado:\n{ioc_csv}")
            return

        self._run_btn.configure(state="disabled")
        self._open_results_btn.configure(state="disabled")
        self._progress.start(10)
        self._console.configure(state="normal")
        self._console.delete("1.0", "end")
        self._console.configure(state="disabled")

        threading.Thread(
            target=self._worker,
            args=(log_file, ioc_csv, output_file, ioc_only, extract_ips),
            daemon=True,
        ).start()
        self._poll()

    def _worker(self, log_file, ioc_csv, output_file, ioc_only, extract_ips):
        q = self._queue

        def log(msg):
            q.put(("log", msg))

        try:
            ioc_set: set = set()
            ioc_map: dict = {}

            if ioc_csv:
                ioc_map = load_iocs_csv(ioc_csv)
                ioc_set = set(ioc_map.keys())
                log(f"[+] IOC CSV:   {len(ioc_map):,} IPs  ({ioc_csv})")

            ts = datetime.now().strftime("%Y%m%d-%H%M")
            output_file = output_file or f"{ts}_CIM_PARSED.csv"

            log(f"[+] Leyendo:   {log_file}")
            total_lines = sum(
                1 for _ in open(log_file, encoding="utf-8", errors="replace")
            )
            log(f"[+] Líneas:    {total_lines:,}")

            parsed = 0
            skipped = 0
            ioc_hits = 0
            last_pct = -1
            unique_ips: set = set()

            with (
                open(log_file, encoding="utf-8", errors="replace") as fin,
                open(output_file, "w", newline="", encoding="utf-8-sig") as fout,
            ):
                writer = csv.DictWriter(
                    fout, fieldnames=CIM_COLUMNS, extrasaction="ignore"
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

                    if ioc_only and not has_ioc:
                        continue

                    writer.writerow({col: record.get(col, "") for col in CIM_COLUMNS})
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
            log(f"[+] IOC hits:   {ioc_hits:,} registros")
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
            # Actualizar combobox de columnas en la pestaña Análisis
            extra = [c for c in cols if c not in _PIVOT_FIELDS]
            self._pivot_col_cb["values"] = _PIVOT_FIELDS + extra
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

    def _apply_filter(self):
        text = self._filter_var.get().strip().lower()
        col = self._filter_col_var.get()
        if not text:
            self._setup_tree(self._csv_columns, self._all_rows)
            self._status_var.set(f"{len(self._all_rows):,} filas (sin filtro)")
            return
        if col == "(todas)":
            filtered = [
                r for r in self._all_rows if any(text in str(v).lower() for v in r)
            ]
        else:
            idx = self._csv_columns.index(col) if col in self._csv_columns else -1
            filtered = [
                r for r in self._all_rows if idx >= 0 and text in str(r[idx]).lower()
            ]
        self._setup_tree(self._csv_columns, filtered)
        self._status_var.set(
            f"{len(filtered):,} de {len(self._all_rows):,} filas filtradas"
        )

    def _clear_filter(self):
        self._filter_var.set("")
        self._setup_tree(self._csv_columns, self._all_rows)
        self._status_var.set(f"{len(self._all_rows):,} filas (sin filtro)")

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
            ctrl, textvariable=self._pivot_col_var, values=_PIVOT_FIELDS, width=22,
        )
        self._pivot_col_cb.pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Métrica:").pack(anchor="w")
        self._pivot_metric_var = tk.StringVar(value="Recuento")
        ttk.Combobox(
            ctrl, textvariable=self._pivot_metric_var,
            values=_PIVOT_METRICS, state="readonly", width=22,
        ).pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="Top N:").pack(anchor="w")
        topn_row = ttk.Frame(ctrl)
        topn_row.pack(fill="x", pady=(0, 8))
        self._pivot_topn_var = tk.StringVar(value="15")
        tk.Spinbox(
            topn_row, from_=5, to=200, increment=5,
            textvariable=self._pivot_topn_var, width=7,
        ).pack(side="left")
        self._pivot_topn_all = tk.BooleanVar()
        ttk.Checkbutton(topn_row, text="Todos", variable=self._pivot_topn_all).pack(side="left", padx=6)

        self._pivot_ioc_only_var = tk.BooleanVar()
        ttk.Checkbutton(ctrl, text="Solo IOC hits", variable=self._pivot_ioc_only_var).pack(anchor="w", pady=(0, 8))

        ttk.Label(ctrl, text="Tipo de gráfico:").pack(anchor="w")
        self._pivot_chart_var = tk.StringVar(value="Barras horizontales")
        ttk.Combobox(
            ctrl, textvariable=self._pivot_chart_var,
            values=_CHART_TYPES, state="readonly", width=22,
        ).pack(fill="x", pady=(0, 10))

        ttk.Button(ctrl, text="▶  Generar", command=self._generate_pivot).pack(fill="x")
        ttk.Button(ctrl, text="💾  Exportar imagen…", command=self._export_chart).pack(fill="x", pady=(4, 0))
        ttk.Separator(ctrl, orient="horizontal").pack(fill="x", pady=8)

        # Accesos rápidos
        ttk.Label(ctrl, text="Accesos rápidos:", font=("", 9, "bold")).pack(anchor="w", pady=(0, 4))
        presets = [
            ("Top IPs origen",      "src_ip",          "Recuento",         "Barras horizontales"),
            ("Acciones fw",         "action",           "Recuento",         "Quesito (pie)"),
            ("Aplicaciones",        "app",              "Recuento",         "Barras horizontales"),
            ("Puertos destino",     "dest_port",        "Recuento",         "Barras horizontales"),
            ("País destino (IOC)",  "ioc_dst_country",  "Recuento",         "Barras horizontales"),
            ("País origen (IOC)",   "ioc_src_country",  "Recuento",         "Barras horizontales"),
            ("Zona origen",         "src_zone",         "Recuento",         "Quesito (pie)"),
            ("Protocolo",           "transport",        "Recuento",         "Quesito (pie)"),
            ("Vendor / fuente",     "vendor",           "Recuento",         "Barras verticales"),
            ("Reglas firewall",     "rule",             "Recuento",         "Barras horizontales"),
            ("Volumen por IP src",  "src_ip",           "Suma bytes_total", "Barras horizontales"),
            ("Riesgo IOC dst",      "ioc_dst_risk",     "Recuento",         "Barras verticales"),
        ]
        for label, col, metric, chart in presets:
            ttk.Button(
                ctrl, text=label,
                command=lambda c=col, m=metric, ch=chart: self._apply_preset(c, m, ch),
            ).pack(fill="x", pady=1)

        # ── Panel derecho: tabla + gráfico ───────────────────────────────────
        right = ttk.PanedWindow(paned, orient="vertical")
        paned.add(right, weight=1)

        # Tabla pivot
        tbl_frame = ttk.LabelFrame(right, text="Tabla pivot", padding=4)
        right.add(tbl_frame, weight=1)
        self._pivot_tree = ttk.Treeview(tbl_frame, show="headings", height=8)
        vsb_p = ttk.Scrollbar(tbl_frame, orient="vertical", command=self._pivot_tree.yview)
        self._pivot_tree.configure(yscrollcommand=vsb_p.set)
        self._pivot_tree.pack(side="left", fill="both", expand=True)
        vsb_p.pack(side="right", fill="y")

        # Área de gráfico
        chart_frame = ttk.LabelFrame(right, text="Gráfico", padding=4)
        right.add(chart_frame, weight=2)

        if _HAS_MPL:
            self._fig = Figure(figsize=(7, 4), dpi=96, facecolor="#f8f8f8")
            self._canvas_mpl = FigureCanvasTkAgg(self._fig, master=chart_frame)
            self._canvas_mpl.get_tk_widget().pack(fill="both", expand=True)
        else:
            self._canvas_mpl = None
            ttk.Label(
                chart_frame,
                text="matplotlib no disponible.\nInstala con:  pip install matplotlib",
                justify="center", foreground="gray",
            ).pack(expand=True)

    def _apply_preset(self, col: str, metric: str, chart: str):
        self._pivot_col_var.set(col)
        self._pivot_metric_var.set(metric)
        self._pivot_chart_var.set(chart)
        self._generate_pivot()

    def _generate_pivot(self):
        if not self._all_rows or not self._csv_columns:
            messagebox.showwarning(
                "Sin datos",
                "Carga primero un CSV en la pestaña Resultados o desde allí.",
            )
            return

        col = self._pivot_col_var.get().strip()
        if col not in self._csv_columns:
            messagebox.showerror("Error", f"Columna '{col}' no encontrada en los datos.")
            return

        metric     = self._pivot_metric_var.get()
        col_idx    = self._csv_columns.index(col)

        # Columna de métrica numérica
        metric_col_idx  = None
        metric_label    = "Recuento"
        if metric != "Recuento":
            metric_col_name = metric.replace("Suma ", "")
            if metric_col_name in self._csv_columns:
                metric_col_idx = self._csv_columns.index(metric_col_name)
                metric_label   = metric

        # Filtro IOC only
        rows = self._all_rows
        if self._pivot_ioc_only_var.get():
            idx_s = self._csv_columns.index("ioc_src") if "ioc_src" in self._csv_columns else -1
            idx_d = self._csv_columns.index("ioc_dst") if "ioc_dst" in self._csv_columns else -1
            rows  = [
                r for r in rows
                if (idx_s >= 0 and r[idx_s] == "YES") or (idx_d >= 0 and r[idx_d] == "YES")
            ]

        # Agrupación
        agg: dict = defaultdict(float)
        for row in rows:
            key = row[col_idx] or "(vacío)"
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
        total  = sum(values) or 1

        # ── Actualizar tabla pivot ────────────────────────────────────────────
        tree = self._pivot_tree
        tree.delete(*tree.get_children())
        tree["columns"] = (col, metric_label, "% total")
        tree.heading(col,          text=col)
        tree.heading(metric_label, text=metric_label)
        tree.heading("% total",    text="% total")
        tree.column(col,          width=200, minwidth=80)
        tree.column(metric_label, width=110, minwidth=60)
        tree.column("% total",    width=80,  minwidth=50)
        for lbl, val in zip(labels, values):
            disp = f"{val:,.0f}" if val == int(val) else f"{val:,.1f}"
            tree.insert("", "end", values=(lbl, disp, f"{val / total * 100:.1f}%"))

        # ── Dibujar gráfico ───────────────────────────────────────────────────
        if self._canvas_mpl is not None:
            self._draw_chart(labels, values, col, metric_label, self._pivot_chart_var.get())

        self._nb.select(self._tab_analysis)

    def _draw_chart(self, labels: list, values: list, col: str, metric: str, chart_type: str):
        self._fig.clear()
        ax    = self._fig.add_subplot(111)
        n     = len(labels)
        colors = (_CHART_COLORS * ((n // len(_CHART_COLORS)) + 1))[:n]

        if chart_type == "Barras horizontales":
            y_pos = list(range(n))
            ax.barh(y_pos, values, color=colors)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(labels, fontsize=8)
            ax.invert_yaxis()
            ax.set_xlabel(metric, fontsize=9)
            for i, v in enumerate(values):
                ax.text(v, i, f"  {v:,.0f}", va="center", fontsize=7)

        elif chart_type == "Barras verticales":
            x_pos = list(range(n))
            ax.bar(x_pos, values, color=colors)
            ax.set_xticks(x_pos)
            ax.set_xticklabels(labels, rotation=40, ha="right", fontsize=8)
            ax.set_ylabel(metric, fontsize=9)

        elif chart_type == "Quesito (pie)":
            wedge = {"edgecolor": "white", "linewidth": 1.2}
            ax.pie(
                values, labels=labels, autopct="%1.1f%%",
                colors=colors, wedgeprops=wedge,
                textprops={"fontsize": 8},
            )

        elif chart_type == "Línea":
            x_pos = list(range(n))
            ax.plot(x_pos, values, marker="o", color=colors[0], linewidth=2)
            ax.fill_between(x_pos, values, alpha=0.15, color=colors[0])
            ax.set_xticks(x_pos)
            ax.set_xticklabels(labels, rotation=40, ha="right", fontsize=8)
            ax.set_ylabel(metric, fontsize=9)

        ax.set_title(f"{col}  —  {metric}", fontsize=10, pad=10)
        self._fig.tight_layout()
        self._canvas_mpl.draw()

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
                ("PDF vectorial",      "*.pdf"),
                ("SVG vectorial",      "*.svg"),
                ("JPEG",               "*.jpg"),
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
    args = parser.parse_args()

    # ── Validar entrada ───────────────────────────────────────────────────────
    if not os.path.isfile(args.log_file):
        print(f"[!] No encontrado: {args.log_file}", file=sys.stderr)
        sys.exit(1)

    # ── Cargar IOC CSV (output de IOCsOfSpades) ───────────────────────────────
    ioc_set: set = set()  # IPs presentes en el ULTRA CSV (para hit rápido)
    ioc_map: dict = {}

    if args.ioc_csv:
        if os.path.isfile(args.ioc_csv):
            ioc_map = load_iocs_csv(args.ioc_csv)
            ioc_set = set(ioc_map.keys())
            print(f"[+] IOC CSV:   {len(ioc_map):,} IPs  ({args.ioc_csv})")
        else:
            print(f"[!] --ioc-csv no encontrado: {args.ioc_csv}", file=sys.stderr)

    # ── Fichero de salida (BOM UTF-8 para Excel) ──────────────────────────────
    ts = datetime.now().strftime("%Y%m%d-%H%M")
    output_file = args.output or f"{ts}_CIM_PARSED.csv"

    # ── Contar líneas para progreso ───────────────────────────────────────────
    print(f"[+] Leyendo:   {args.log_file}")
    total_lines = sum(
        1 for _ in open(args.log_file, encoding="utf-8", errors="replace")
    )
    print(f"[+] Líneas:    {total_lines:,}")

    # ── Parsear ───────────────────────────────────────────────────────────────
    parsed = 0
    skipped = 0
    ioc_hits = 0
    last_pct = -1
    unique_ips: set = set()  # para --extract-ips

    with (
        open(args.log_file, encoding="utf-8", errors="replace") as fin,
        open(output_file, "w", newline="", encoding="utf-8-sig") as fout,
    ):
        writer = csv.DictWriter(fout, fieldnames=CIM_COLUMNS, extrasaction="ignore")
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

            if args.ioc_only and not has_ioc:
                continue

            # Escribir fila CIM
            writer.writerow({col: record.get(col, "") for col in CIM_COLUMNS})
            parsed += 1

    # ── Exportar IPs únicas para IOCsOfSpades ────────────────────────────────
    if args.extract_ips and unique_ips:
        with open(args.extract_ips, "w", encoding="utf-8") as f:
            for ip in sorted(unique_ips):
                f.write(ip + "\n")
        print(f"\n[+] IPs únicas: {len(unique_ips):,}  →  {args.extract_ips}")

    # ── Resumen ───────────────────────────────────────────────────────────────
    print()
    print("─" * 50)
    print(f"[+] Procesados: {parsed + skipped:,}")
    print(f"[+] Exportados: {parsed:,} registros CIM")
    print(f"[+] Ignorados:  {skipped:,} líneas (formato no reconocido)")
    print(f"[+] IOC hits:   {ioc_hits:,} registros")
    print(f"[+] Salida:     {output_file}")
    print("─" * 50)


if __name__ == "__main__":
    main()
