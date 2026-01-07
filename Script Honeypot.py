#!/usr/bin/env python3

import re
import ipaddress
from pathlib import Path
from datetime import datetime
import glob
import time

LOG_FILE = Path("/home/dco/Honeypot/output.log")
OUT_DIR  = Path("/var/www/html/blacklist")
SRC_IP_RE = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')

# ------------------------------------------------------
def is_public_ip(ipstr):
    try:
        ip = ipaddress.ip_address(ipstr)
        return ip.is_global
    except ValueError:
        return False

# ------------------------------------------------------
def rebuild_master_index(directory="/var/www/html/blacklist"):
    output_file = f"{directory}/index_all.txt"
    all_entries = []

    for file in glob.glob(f"{directory}/blacklist-*.txt"):
        with open(file, "r") as f:
            for line in f:
                if line.strip():
                    all_entries.append(line.strip())

    with open(output_file, "w") as f:
        for entry in sorted(all_entries):
            f.write(entry + "\n")

    print(f"[INDEX] Updated ({len(all_entries)} entries)")

# ------------------------------------------------------
def write_ip(ip, tag):
    today = datetime.utcnow().strftime("%Y%m%d")
    timestamp_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    out_file = OUT_DIR / f"blacklist-{today}.txt"

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Load existing to avoid duplicates
    existing = set()
    if out_file.exists():
        with out_file.open() as f:
            for line in f:
                ip_only = line.split("|")[0].strip()
                existing.add(ip_only)

    if ip in existing:
        return  # skip duplicate

    with out_file.open("a") as f:
        f.write(f"{ip} | {timestamp_now} | {tag}\n")

    print(f"[NEW] {ip} ({tag}) added")

    rebuild_master_index(str(OUT_DIR))

# ------------------------------------------------------
def main():
    print("[*] Real-time Honeypot Monitor Started...")
    print(f"    Watching: {LOG_FILE}")

    if not LOG_FILE.exists():
        print("Log file not found!")
        return

    with LOG_FILE.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)   # Go to end of file

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.2)
                continue

            m = SRC_IP_RE.search(line)
            if not m:
                continue

            src_ip = m.group(1)
            tag = "PUBLIC" if is_public_ip(src_ip) else "PRIVATE"

            write_ip(src_ip, tag)


if __name__ == "__main__":
    main()
