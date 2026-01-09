#!/usr/bin/env python3

import re
import ipaddress
from pathlib import Path
from datetime import datetime
import glob

LOG_FILE = Path("/var/log/syslog")
OUT_DIR = Path("/var/www/html/blacklist")

# IP yang diizinkan setelah "to"
ALLOWED_TO_IPS = {
    "10.102.101.12",
    "10.102.101.13",
    "10.102.101.14",
    "10.102.101.15"
}

# Regex tangkap: dari log UNIX (Jan 8 02:17:01)
UNIX_TIME_RE = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)')

# Regex ambil IP setelah from ... to ...
LOG_RE = re.compile(
    r'from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+to\s+(\d{1,3}(?:\.\d{1,3}){3})'
)

MONTH_MAP = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
}

def parse_unix_timestamp(line):
    """Parse timestamp UNIX-style syslog → return YYYY-MM-DD HH:MM:SS"""
    m = UNIX_TIME_RE.match(line)
    if not m:
        return None, None  # fallback to today

    mon, day, hms = m.groups()
    month = MONTH_MAP[mon]

    # Tahun harus dari current year karena syslog tidak menyimpan tahun
    year = datetime.utcnow().year

    datestr = f"{year}-{month}-{int(day):02d}"
    timestr = f"{datestr} {hms}"

    return datestr, timestr


def is_public_ip(ipstr):
    try:
        ip = ipaddress.ip_address(ipstr)
        return ip.is_global
    except:
        return False


def rebuild_master_index():
    index = {}

    for file in glob.glob(f"{OUT_DIR}/blacklist-*.txt"):
        with open(file, "r") as f:
            for line in f:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) != 3:
                    continue
                ip, ts, iptype = parts

                if ip not in index:
                    index[ip] = {"timestamps": [], "type": iptype}

                index[ip]["timestamps"].append(ts)

    with open(OUT_DIR / "index_all.txt", "w") as idx:
        for ip in sorted(index.keys()):
            tss = ", ".join(sorted(index[ip]["timestamps"]))
            idx.write(f"{ip} | {tss} | {index[ip]['type']}\n")


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("r", errors="ignore") as fh:
        for line in fh:

            # ambil IP from & to
            m = LOG_RE.search(line)
            if not m:
                continue

            src_ip, dst_ip = m.groups()

            # Filter: hanya IP to yang allowed
            if dst_ip not in ALLOWED_TO_IPS:
                continue

            # Parse UNIX timestamp (tanggal log asli)
            file_date, full_timestamp = parse_unix_timestamp(line)
            if not file_date:
                continue

            out_file = OUT_DIR / f"blacklist-{file_date}.txt"

            # avoid duplicate
            existing = set()
            if out_file.exists():
                with out_file.open("r") as f:
                    for l in f:
                        existing.add(l.split("|")[0].strip())

            if src_ip in existing:
                continue

            iptype = "PUBLIC" if is_public_ip(src_ip) else "PRIVATE"

            with out_file.open("a") as f:
                f.write(f"{src_ip} | {full_timestamp} | {iptype}\n")

    rebuild_master_index()


if __name__ == "__main__":
    main()
