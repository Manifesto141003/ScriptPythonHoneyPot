#!/usr/bin/env python3

import re
import ipaddress
from pathlib import Path
from datetime import datetime

# CONFIG
LOG_FILE = Path("/home/dco/Honeypot/output.log")
OUT_DIR  = Path("/var/www/blacklist")

# regex ambil IP setelah kata 'from'
SRC_IP_RE = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')

def is_public_ip(ipstr):
    try:
        ip = ipaddress.ip_address(ipstr)
        return ip.is_global
    except ValueError:
        return False

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    today = datetime.utcnow().strftime("%Y%m%d")
    out_file = OUT_DIR / f"blacklist-{today}.txt"

    # load existing IPs (kalau file hari ini sudah ada)
    existing_ips = set()
    if out_file.exists():
        with out_file.open("r") as fh:
            for line in fh:
                existing_ips.add(line.strip())

    new_ips = set()

    with LOG_FILE.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = SRC_IP_RE.search(line)
            if not m:
                continue

            src_ip = m.group(1)
            if is_public_ip(src_ip) and src_ip not in existing_ips:
                new_ips.add(src_ip)

    if not new_ips:
        print("No new public IPs found.")
        return

    # append ke file harian
    with out_file.open("a") as fh:
        for ip in sorted(new_ips):
            fh.write(ip + "\n")

    print(f"Added {len(new_ips)} IP(s) to {out_file}")

if __name__ == "__main__":
    main()
