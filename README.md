# MasterOfParser

**🖤 `masterof_puppets` 🖤**

**PARSE LOUD. PIVOT HARD.**

Firewall logs don't investigate themselves. MasterOfParser takes raw firewall events and QRadar exports, normalizes them into a CIM-style CSV, and gives you a desktop workspace to figure out what the hell happened.

## What it handles

- **Firewall payloads:** Palo Alto Networks LEEF 2.0 (pipe-separated attributes), Fortinet key-value events with source and destination IPs, and Cisco FTD `313005` events containing the original IP payload. Supported raw formats are detected line by line, so they can live in the same file.
- **File inputs:** raw logs (one event per line), QRadar CSV/TSV exports with a `Payload` column at the end, and pre-parsed CSVs with CIM-style IP fields.
- **IOC correlation:** import results from [IOCs of Spades](https://github.com/Martixx/IOCsOfSpades) and match source and destination IPs, including NAT addresses when available. The parser reads the enrichment files locally; it does not query VirusTotal for you.
- **Desktop triage:** filter events, build pivots and time histograms, flag volume spikes, cross-reference an ASN reputation list, and export CSVs and charts. Import an IPAPI CSV in the GUI for additional context and heuristic beaconing triage.

## Fire it up

Use **Python 3.10+** with **Tkinter** available. Install `pandas` for dataframe-based analysis and `matplotlib` for charts. `squarify` is optional for treemaps.

```bash
python -m pip install pandas matplotlib
python MasterOfParser.py
```

Running without arguments opens the desktop app. The UI is mostly in Spanish: choose an input under **Parser**, click **Ejecutar**, then open **Resultados** to start digging. Use `python3` instead of `python` if that's how your system launches Python 3.

## CLI quick start

For a quick smoke test, save this synthetic Fortinet event as `firewall.log`:

```text
date=2026-01-15 time=12:00:00 devname=demo-fw type=traffic subtype=forward srcip=192.0.2.10 srcport=51514 dstip=198.51.100.20 dstport=443 proto=6 action=accept sentbyte=420 rcvdbyte=900
```

Parse the file and extract unique source and destination IPs:

```bash
python MasterOfParser.py firewall.log --output parsed.csv --extract-ips ips.txt
```

The main output is a UTF-8 CSV with a BOM. Use a different filename from the input to avoid overwriting it.

For an authorized investigation, enrich the extracted IPs separately with IOCs of Spades, then feed its exports back into the parser:

```bash
python MasterOfParser.py firewall.log --ioc-csv ULTRA.csv --osint-csv ULTRA_OSINT.csv --output enriched.csv
```

- Add `--ioc-only` to keep only events that meet the tool's IOC alert criteria. Appearing in an input CSV is not enough to count as a hit.
- Add `--raw-event` to retain the original payload for raw log inputs and QRadar exports.
- Run `python MasterOfParser.py --help` for the full CLI options.

## Keep the evidence where it belongs

IOC hits, reputation scores, and beaconing candidates are leads, not verdicts. Keep the original logs for validation. Don't publish real logs, exported results, or screenshots containing customer data. Before sending extracted IPs to any external enrichment service, make sure that use is authorized. For untrusted exports, import CSV fields as text rather than letting a spreadsheet evaluate them as formulas.

**Less scrolling. More investigating.**

## Bonus track: B-side

*The bass is buried in the mix.*

`75e12811e812f22edc24d9e96534a0b41fad81d4d9880dfa915b88de7e92f5ca2b77d747f7c093e630851cce504f85a9`

<!--
Track 02 / B-side

Keep the master. Replace the parser with the figures he controls by strings.
Sixteen characters. All lowercase, no spaces, one underscore right after "of".

Cipher: AES-128-CBC
Key and IV encoding: UTF-8
IV: cliff_bass_solo!
Ciphertext encoding: hex
-->
