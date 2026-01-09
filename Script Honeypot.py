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

# IP honeypot internal yang HARUS di-exclude
EXCLUDED_IPS = {
    "10.102.101.12",  # hnn01
    "10.102.101.13",  # hnn02
    "10.102.101.14",  # hnn03
    "10.102.101.15",  # hnn04
    "10.102.101.44",  # IP tambahan yang kamu exclude
}

# Port yang tidak dianggap port scan (false positive)
EXCLUDED_PORTS = {7680, 8289, 14062}

# Regex ambil IP hanya dari “from <ip>”, TIDAK ambil yang setelah "to"
SRC_IP_RE = re.compile(
    r'from\s+((?:\d{1,3}\.){3}\d{1,3})(?!\s*to)'     # ambil IP setelah from
    r'|::ffff:((?:\d{1,3}\.){3}\d{1,3})'             # cowrie IPv6 mapped
)

# Ambil port bila ada
PORT_RE = re.compile(r'port\s+(\d+)')


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


def get_log_file_name(line):
    """Gunakan tanggal log, atau fallback hari ini."""
    m = re.search(r'(\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}', line)
    if m:
        y, mo, d = m.group(1).split("-")
        return OUT_DIR / f"blacklist-{y}{mo}{d}.txt"

    today = datetime.utcnow().strftime("%Y%m%d")
    return OUT_DIR / f"blacklist-{today}.txt"


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

            # ---------------------------
            # 1. Ambil IP sumber
            # ---------------------------
            m = SRC_IP_RE.search(line)
            if not m:
                continue

            src_ip = m.group(1) or m.group(2)
            if not src_ip:
                continue

            # ---------------------------
            # 2. Exclude IP tertentu
            # ---------------------------
            if src_ip in EXCLUDED_IPS:
                continue

            # ---------------------------
            # 3. Ambil port (jika ada)
            # ---------------------------
            pm = PORT_RE.search(line)
            if pm:
                port = int(pm.group(1))

                # skip port tertentu
                if port in EXCLUDED_PORTS:
                    continue

            # ---------------------------
            # 4. PUBLIC vs PRIVATE
            # ---------------------------
            tag = "PUBLIC" if is_public_ip(src_ip) else "PRIVATE"
            timestamp_now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            # ---------------------------
            # 5. Tentukan file blacklist target berdasarkan tanggal log
            # ---------------------------
            out_file = get_log_file_name(line)
            out_file.parent.mkdir(parents=True, exist_ok=True)

            # ---------------------------
            # 6. Hindari duplikasi IP
            # ---------------------------
            existing_ips = set()
            if out_file.exists():
                with out_file.open("r") as fh_exist:
                    for l in fh_exist:
                        existing_ips.add(l.split("|")[0].strip())

            if src_ip in existing_ips:
                continue

            # ---------------------------
            # 7. Tulis IP baru ke file blacklist
            # ---------------------------
            with out_file.open("a") as fh_append:
                fh_append.write(f"{src_ip} | {timestamp_now} | {tag}\n")
                new_ips_total += 1

    print(f"Added {new_ips_total} new unique IP(s)")
    rebuild_master_index(OUT_DIR)


# =====================================================================
# RUN
# =====================================================================
if __name__ == "__main__":
    main()
