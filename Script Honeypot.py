#!/usr/bin/env python3
import re
import datetime
import os

SYSLOG_PATH = "/var/log/syslog"

HONEYPOT_IPS = {
    "10.102.101.12": "hnn01",
    "10.102.101.13": "hnn02",
    "10.102.101.14": "hnn03",
    "10.102.101.15": "hnn04",
}

def extract_date_from_syslog_line(line):
    """Ambil tanggal dari format default syslog: 'Jan  8 06:31:04' """
    try:
        parts = line.split()
        month = parts[0]
        day = parts[1]
        year = datetime.datetime.now().year  # syslog tidak ada tahun
        date_str = f"{month} {day} {year}"
        date_obj = datetime.datetime.strptime(date_str, "%b %d %Y")
        return date_obj.strftime("%Y-%m-%d")
    except:
        return None

def process_syslog():
    if not os.path.exists(SYSLOG_PATH):
        print("Syslog tidak ditemukan.")
        return

    with open(SYSLOG_PATH, "r") as f:
        lines = f.readlines()

    # Regex match IP
    ip_regex = r"10\.102\.101\.\d+"

    for line in lines:
        date_str = extract_date_from_syslog_line(line)
        if not date_str:
            continue
        
        # Nama blacklist sesuai tanggal log
        blacklist_file = f"/var/www/html/blacklist/blacklist-{date_str}.txt"

        # Ambil semua IP valid di line
        ips = re.findall(ip_regex, line)
        if not ips:
            continue

        # Pastikan file ada
        if not os.path.exists(blacklist_file):
            open(blacklist_file, "a").close()

        # Masukkan IP ke file blacklist (tanpa duplikat)
        with open(blacklist_file, "r+") as bf:
            existing = bf.read().split()

            for ip in ips:
                if ip in existing:
                    continue  # skip duplicate

                # Jika IP ada di mapping internal → tambahkan nama host
                label = HONEYPOT_IPS.get(ip, "")
                if label:
                    bf.write(f"{ip} ({label})\n")
                else:
                    bf.write(f"{ip}\n")

    print("Selesai update blacklist berdasarkan syslog.")

if __name__ == "__main__":
    process_syslog()
