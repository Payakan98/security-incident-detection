# src/ingest.py
import os
import csv
import json
import glob
import subprocess
from datetime import datetime, timezone
import pandas as pd
from dateutil import parser as date_parser

# Optional: import mailparser if installed
try:
    import mailparser
except Exception:
    mailparser = None

RAW_DIR = os.path.join("data", "raw")
PROC_DIR = os.path.join("data", "processed")
OUT_CSV = os.path.join(PROC_DIR, "events.csv")

# Target fields
FIELDS = ["ts","src_ip","dst_ip","src_port","dst_port","proto","event_type","event_subtype","payload_size","raw_message"]

os.makedirs(PROC_DIR, exist_ok=True)

def isoutc(ts):
    """Return ISO UTC string from epoch or datetime-like input"""
    if ts is None:
        return ""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    try:
        return date_parser.parse(str(ts)).astimezone(timezone.utc).isoformat()
    except Exception:
        return str(ts)

def write_rows(rows):
    df = pd.DataFrame(rows, columns=FIELDS)
    # ensure columns exist
    for c in FIELDS:
        if c not in df.columns:
            df[c] = ""
    df.to_csv(OUT_CSV, index=False)
    print(f"[+] Wrote {len(df)} rows to {OUT_CSV}")

# --- PCAP ingestion via tshark (fast) ---
def ingest_pcap_with_tshark(pcap_path):
    # fields: epoch time, ip.src, ip.dst, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, protocol, frame.len
    cmd = [
        "tshark", "-r", pcap_path, "-T", "fields",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "_ws.col.Protocol", "-e", "frame.len",
        "-E", "header=y", "-E", "separator=|"
    ]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
    except Exception as e:
        print("[!] tshark failed or not available:", e)
        return []
    rows = []
    for i, line in enumerate(out.splitlines()):
        if i == 0 and "frame.time_epoch" in line:
            continue
        parts = line.split("|")
        # safe indexing
        def get(n): return parts[n] if n < len(parts) else ""
        ts = get(0)
        src = get(1)
        dst = get(2)
        tcp_s = get(3)
        tcp_d = get(4)
        udp_s = get(5)
        udp_d = get(6)
        proto = get(7)
        pkt_len = get(8)
        src_port = tcp_s or udp_s or ""
        dst_port = tcp_d or udp_d or ""
        raw = f"pcap:{os.path.basename(pcap_path)}"
        rows.append({
            "ts": isoutc(float(ts)) if ts else "",
            "src_ip": src,
            "dst_ip": dst,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "event_type": "pcap_packet",
            "event_subtype": "",
            "payload_size": pkt_len,
            "raw_message": raw
        })
    print(f"[+] Parsed {len(rows)} packets from {pcap_path} with tshark")
    return rows

# --- Fallback PCAP ingestion via pyshark (slower) ---
def ingest_pcap_with_pyshark(pcap_path):
    try:
        import pyshark
    except Exception:
        print("[!] pyshark not installed; skipping pcap ingestion for", pcap_path)
        return []
    cap = pyshark.FileCapture(pcap_path)
    rows = []
    for pkt in cap:
        try:
            ts = getattr(pkt, 'sniff_timestamp', None) or getattr(pkt, 'frame_info', {}).get('time_epoch', None)
            ts = float(ts) if ts else None
            src = getattr(pkt.ip, 'src', "")
            dst = getattr(pkt.ip, 'dst', "")
            proto = pkt.transport_layer if hasattr(pkt, 'transport_layer') else getattr(pkt, 'highest_layer', "")
            src_port = getattr(pkt[pkt.transport_layer], 'srcport', "") if hasattr(pkt, 'transport_layer') else ""
            dst_port = getattr(pkt[pkt.transport_layer], 'dstport', "") if hasattr(pkt, 'transport_layer') else ""
            pkt_len = getattr(pkt, 'length', "") or getattr(pkt.frame_info, 'len', "")
            rows.append({
                "ts": isoutc(ts) if ts else "",
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto,
                "event_type": "pcap_packet",
                "event_subtype": "",
                "payload_size": pkt_len,
                "raw_message": f"pcap:{os.path.basename(pcap_path)}"
            })
        except Exception:
            continue
    print(f"[+] Parsed {len(rows)} packets from {pcap_path} with pyshark")
    return rows

# --- Suricata / IDS JSON ingestion (eve.json lines) ---
def ingest_suricata_json(json_path):
    rows = []
    with open(json_path, 'r', errors='ignore') as f:
        for line in f:
            try:
                j = json.loads(line)
            except Exception:
                continue
            # suricata eve.json typical structure: keys like 'timestamp','src_ip','dest_ip','event_type' or 'alert'
            ts = j.get('timestamp') or j.get('@timestamp') or j.get('ts')
            src = j.get('src_ip') or j.get('source_ip') or j.get('src')
            dst = j.get('dest_ip') or j.get('destination_ip') or j.get('dst')
            proto = j.get('proto') or j.get('protocol') or ""
            payload_size = j.get('payload_len') or j.get('length') or ""
            event_type = j.get('event_type') or (j.get('alert',{}).get('signature','alert') if 'alert' in j else "ids_alert")
            subtype = ""
            if 'alert' in j:
                subtype = j['alert'].get('signature','')
            rows.append({
                "ts": isoutc(ts),
                "src_ip": src,
                "dst_ip": dst,
                "src_port": j.get('src_port') or j.get('sport') or "",
                "dst_port": j.get('dest_port') or j.get('dport') or "",
                "proto": proto,
                "event_type": event_type,
                "event_subtype": subtype,
                "payload_size": payload_size,
                "raw_message": json.dumps(j)[:2000]
            })
    print(f"[+] Parsed {len(rows)} events from {json_path}")
    return rows

# --- Emails ingestion (.eml) ---
def ingest_eml(file_path):
    rows = []
    if mailparser:
        mp = mailparser.parse_from_file(file_path)
        ts = mp.date and mp.date.isoformat() or ""
        src = mp.from_[0][1] if mp.from_ else ""
        subject = mp.subject or ""
        raw = f"email:{os.path.basename(file_path)} subject:{subject}"
        # Try to extract urls from body
        urls = mp.urls if hasattr(mp, 'urls') else []
        rows.append({
            "ts": isoutc(ts),
            "src_ip": "",
            "dst_ip": "",
            "src_port": "",
            "dst_port": "",
            "proto": "email",
            "event_type": "email",
            "event_subtype": subject,
            "payload_size": "",
            "raw_message": raw + " urls:" + ",".join(urls)
        })
        return rows
    else:
        # fallback: parse headers with email package
        from email import policy
        from email.parser import BytesParser
        with open(file_path,'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        ts = msg['Date']
        src = msg['From']
        subject = msg['Subject']
        raw = f"email:{os.path.basename(file_path)} subject:{subject}"
        return [{
            "ts": isoutc(ts),
            "src_ip": "",
            "dst_ip": "",
            "src_port": "",
            "dst_port": "",
            "proto": "email",
            "event_type": "email",
            "event_subtype": subject or "",
            "payload_size": "",
            "raw_message": raw
        }]

def main():
    all_rows = []

    # 1) PCAP files
    for pcap in glob.glob(os.path.join(RAW_DIR, "*.pcap")) + glob.glob(os.path.join(RAW_DIR, "*.pcapng")):
        # prefer tshark if available
        try:
            subprocess.check_output(["tshark", "-v"], stderr=subprocess.DEVNULL)
            rows = ingest_pcap_with_tshark(pcap)
        except Exception:
            rows = ingest_pcap_with_pyshark(pcap)
        all_rows.extend(rows)

    # 2) Suricata / IDS JSON files (any .json that looks like eve)
    for jfile in glob.glob(os.path.join(RAW_DIR, "*.json")):
        all_rows.extend(ingest_suricata_json(jfile))

    # 3) EML files
    for eml in glob.glob(os.path.join(RAW_DIR, "*.eml")):
        all_rows.extend(ingest_eml(eml))

    # 4) folders of emails (optional)
    email_dir = os.path.join(RAW_DIR, "emails")
    if os.path.isdir(email_dir):
        for eml in glob.glob(os.path.join(email_dir, "*.eml")):
            all_rows.extend(ingest_eml(eml))

    # Final write
    if all_rows:
        # normalize columns order and fill missing
        normalized = []
        for r in all_rows:
            row = {k: r.get(k, "") for k in FIELDS}
            normalized.append(row)
        write_rows(normalized)
    else:
        print("[!] No events found in data/raw/")

if __name__ == "__main__":
    main()
