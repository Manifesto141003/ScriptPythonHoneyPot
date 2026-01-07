#!/usr/bin/env python3
import re
import ipaddress
from pathlib import Path
from datetime import datetime
import subprocess
import time
import glob

LOG_FILE = Path("/home/dco/Honeypot/output.log")
OUT_DIR  = Path("/var/www/html/blacklist")

SRC_IP_RE = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')

def is_public_ip(ipstr):
    try:
        ip = ipaddress.ip_address(ipstr)
        return ip.is_global
    except:
        return False

def write_ips(ips):
    today = datetime.utcnow().strftime("%Y%m%d")
    timestamp_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    out_file = OUT_DIR / f"blacklist-{today}.txt"

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    existing = set()
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            parts = line.split("|")
            existing.add(parts[0].strip())

    new_ips = [ip for ip in ips if ip not in existing]

    if new_ips:
        with out_file.open("a") as f:
            for ip in sorted(new_ips):
                f.write(f"{ip} | {timestamp_now}\n")

        print(f"[+] Added {len(new_ips)} IP(s)")

def scan_full_file():
    print("[*] Running startup full scan...")
    found = set()

    for line in LOG_FILE.read_text().splitlines():
        m = SRC_IP_RE.search(line)
        if m:
            ip = m.group(1)
            if is_public_ip(ip):
                found.add(ip)

    write_ips(found)

def realtime_tail():
    print("[*] Starting realtime monitor...")
    p = subprocess.Popen(
        ["tail", "-F", str(LOG_FILE)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for line in p.stdout:
        m = SRC_IP_RE.search(line)
        if not m:
            continue

        ip = m.group(1)
        if is_public_ip(ip):
            write_ips([ip])

def main():
    scan_full_file()   # Recovery mode
    realtime_tail()    # Realtime mode

if __name__ == "__main__":
    main()
