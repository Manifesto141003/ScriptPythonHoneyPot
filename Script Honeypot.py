#!/usr/bin/env python3

import re
import ipaddress
from pathlib import Path
from datetime import datetime
import glob

# =====================================================================
# CONFIG
# =====================================================================

LOG_FILE = Path("/var/log/syslog")
OUT_DIR  = Path("/var/www/html/blacklist")

EXCLUDED_IPS = {
    "10.102.101.12",
    "10.102.101.13",
    "10.102.101.14",
    "10.102.101.15",
}

EXCLUDED_PORTS = {7680, 8289, 14062}

# Ambil IP dari "from <ip>" tapi bukan yang setelah "to", dan dari ::ffff: (Cowrie)
SRC_IP_RE = re.compile(
    r'from\s+((?:\d{1,3}\.){3}\d{1,3})(?!\s*to)'
    r'|::ffff:((?:\d{1,3}\.){3}\d{1,3})'
)

PORT_RE = re.compile(r'port\s+(\d+)')

# syslog format: "Jan  9 01:53:10"
SYSLOG_DATE_RE = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+\d{2}:\d{2}:\d{2}')

# cowrie ISO timestamp: 2026-01-08T01:54:10+0000
COWRIE_DATE_RE = re.compile(r'(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}')


# =====================================================================
# FUNCTIONS
# =====================================================================

def is_public_ip(ipstr):
    try:
        ip = ipaddress.ip_address(ipstr)
        return ip.is_global
    except ValueError:
        return False


def rebuild_master_index(directory=OUT_DIR):
    output_file = directory / "index_all.txt"
    all_entries = set()

    for file in glob.glob(f"{directory}/blacklist-*.txt"):
        with open(file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    all_entries.add(line)

    with open(output_file, "w") as f:
        for entry in sorted(all_entries):
            f.write(entry + "\n")

    print(f"Rebuilt index_all.txt with {len(all_entries)} unique entries")


def get_log_datetime(line):
    """Ambil tanggal dari log, syslog atau cowrie"""
    # Cowrie ISO
    m = COWRIE_DATE_RE.search(line)
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%d")

    # Syslog
    m = SYSLOG_DATE_RE.match(line)
    if m:
        month_str, day_str = m.groups()
        month = datetime.strptime(month_str, "%b").month
        day = int(day_str)
        year = datetime.utcnow().year
        return datetime(year, month, day)

    # fallback hari ini
    return datetime.utcnow()


def get_log_file_name(dt: datetime):
    """Buat file blacklist per tanggal log"""
    return OUT_DIR / f"blacklist-{dt.strftime('%Y%m%d')}.txt"


# =====================================================================
# MAIN PROCESS
# =====================================================================

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    new_ips_total = 0

    with LOG_FILE.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:

            # 1. Ambil IP sumber
            m = SRC_IP_RE.search(line)
            if not m:
                continue

            src_ip = m.group(1) or m.group(2)
            if not src_ip:
                continue

            # 2. Exclude IP tertentu
            if src_ip in EXCLUDED_IPS:
                continue

            # 3. Ambil port (jika ada)
            pm = PORT_RE.search(line)
            if pm and int(pm.group(1)) in EXCLUDED_PORTS:
                continue

            # 4. Tentukan PUBLIC vs PRIVATE
            tag = "PUBLIC" if is_public_ip(src_ip) else "PRIVATE"

            # 5. Tentukan file blacklist target berdasarkan tanggal log
            dt = get_log_datetime(line)
            out_file = get_log_file_name(dt)
            out_file.parent.mkdir(parents=True, exist_ok=True)

            # 6. Hindari duplikasi IP di file yang sama
            existing_ips = set()
            if out_file.exists():
                with out_file.open("r") as fh_exist:
                    for l in fh_exist:
                        existing_ips.add(l.split("|")[0].strip())

            if src_ip in existing_ips:
                continue

            # 7. Tulis IP baru
            with out_file.open("a") as fh_append:
                fh_append.write(f"{src_ip} | {tag}\n")
                new_ips_total += 1

    print(f"Added {new_ips_total} new unique IP(s)")
    rebuild_master_index(OUT_DIR)


# =====================================================================
# RUN
# =====================================================================
if __name__ == "__main__":
    main()
