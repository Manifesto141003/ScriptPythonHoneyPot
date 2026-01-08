#!/usr/bin/env python3

import re
import ipaddress
from pathlib import Path
from datetime import datetime
import glob

# =====================================================================
# 1. Build Master Index (index_all.txt)
# =====================================================================
def rebuild_master_index(directory="/var/www/html/blacklist"):
    output_file = f"{directory}/index_all.txt"
    all_entries = set()  # gunakan SET agar 100% tidak ada duplikasi

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


# =====================================================================
# CONFIG
# =====================================================================
LOG_FILE = Path("/var/log/syslog")
OUT_DIR  = Path("/var/www/html/blacklist")

# Ambil IP dari:
# 1) "from 10.x.x.x"
# 2) "::ffff:10.x.x.x"
SRC_IP_RE = re.compile(
    r'from\s+(\d{1,3}(?:\.\d{1,3}){3})|::ffff:(\d{1,3}(?:\.\d{1,3}){3})'
)

def is_public_ip(ipstr):
    try:
        ip = ipaddress.ip_address(ipstr)
        return ip.is_global
    except ValueError:
        return False


# =====================================================================
# 2. MAIN PROCESS
# =====================================================================
def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return

    today = datetime.utcnow().strftime("%Y%m%d")
    timestamp_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    out_file = OUT_DIR / f"blacklist-{today}.txt"

    # Load existing IP only (avoid duplicates)
    existing_ips = set()
    if out_file.exists():
        with out_file.open("r") as fh:
            for line in fh:
                ip_only = line.split("|")[0].strip()
                existing_ips.add(ip_only)

    new_ips = set()

    with LOG_FILE.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = SRC_IP_RE.search(line)
            if not m:
                continue

            # Ambil IP dari grup 1 atau grup 2
            src_ip = m.group(1) or m.group(2)
            if not src_ip:
                continue

            tag = "PUBLIC" if is_public_ip(src_ip) else "PRIVATE"

            # Tambah hanya jika belum ada sebelumnya
            if src_ip not in existing_ips:
                new_ips.add((src_ip, tag))

    if not new_ips:
        print("No new IPs found.")
        return

    # Append IPs with timestamp and tag
    with out_file.open("a") as fh:
        for ip, tag in sorted(new_ips):
            fh.write(f"{ip} | {timestamp_now} | {tag}\n")

    print(f"Added {len(new_ips)} new unique IP(s) to {out_file}")

    # Update master index
    rebuild_master_index(str(OUT_DIR))


# =====================================================================
# RUN
# =====================================================================
if __name__ == "__main__":
    main()
