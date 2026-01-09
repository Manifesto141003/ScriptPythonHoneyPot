#!/usr/bin/env python3

import re
import ipaddress
from pathlib import Path
from datetime import datetime
import glob

# ============================================================
# CONFIG
# ============================================================
LOG_FILE = Path("/var/log/syslog")
OUT_DIR = Path("/var/www/html/blacklist")

# Only allow IPs AFTER "to"
ALLOWED_TO_IPS = {
    "10.102.101.12",
    "10.102.101.13",
    "10.102.101.14",
    "10.102.101.15"
}

# Parse "Jan 8 02:17:01"
UNIX_TIME_RE = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)')

# Parse "from <ip> to <ip>"
LOG_RE = re.compile(
    r'from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+to\s+(\d{1,3}(?:\.\d{1,3}){3})'
)

MONTH_MAP = {
    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
}

# ============================================================
# FUNCTIONS
# ============================================================

def parse_unix_timestamp(line):
    """Return YYYY-MM-DD and full timestamp from syslog line."""
    m = UNIX_TIME_RE.match(line)
    if not m:
        return None, None

    mon, day, hms = m.groups()
    month = MONTH_MAP[mon]
    year = datetime.utcnow().year

    date_str = f"{year}-{month}-{int(day):02d}"
    full_ts = f"{date_str} {hms}"

    return date_str, full_ts


def is_public_ip(ipstr):
    try:
        ip = ipaddress.ip_address(ipstr)
        return ip.is_global
    except:
        return False


def rebuild_master_index():
    """Combine all blacklist-*.txt into index_all.txt"""
    data = {}

    for file in glob.glob(f"{OUT_DIR}/blacklist-*.txt"):
        with open(file, "r") as fh:
            for line in fh:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) != 3:
                    continue

                ip, ts, iptype = parts

                if ip not in data:
                    data[ip] = {"timestamps": [], "type": iptype}

                data[ip]["timestamps"].append(ts)

    # Write merged index
    idx_file = OUT_DIR / "index_all.txt"
    with idx_file.open("w") as f:
        for ip in sorted(data.keys()):
            ts_join = ", ".join(sorted(data[ip]["timestamps"]))
            f.write(f"{ip} | {ts_join} | {data[ip]['type']}\n")


# ============================================================
# MAIN
# ============================================================

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("r", errors="ignore") as fh:
        for line in fh:

            # Find "from X to Y"
            m = LOG_RE.search(line)
            if not m:
                continue

            src_ip, dst_ip = m.groups()

            # Check allowed "to"
            if dst_ip not in ALLOWED_TO_IPS:
                continue

            # Parse actual log timestamp
            date_str, full_ts = parse_unix_timestamp(line)
            if not date_str:
                continue

            # Output file per date
            out_file = OUT_DIR / f"blacklist-{date_str}.txt"

            # Check existing IP (no duplicate)
            existing = set()
            if out_file.exists():
                with out_file.open("r") as f:
                    for l in f:
                        existing.add(l.split("|")[0].strip())

            if src_ip in existing:
                continue

            ip_type = "PUBLIC" if is_public_ip(src_ip) else "PRIVATE"

            # Write new IP entry
            with out_file.open("a") as f:
                f.write(f"{src_ip} | {full_ts} | {ip_type}\n")

    # Rebuild index
    rebuild_master_index()


if __name__ == "__main__":
    main()
