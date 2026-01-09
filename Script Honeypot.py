#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP

# Honeypot IPs & names
HONEYPOT_IPS = {
    "10.102.101.12": "hnn01",
    "10.102.101.13": "hnn02",
    "10.102.101.14": "hnn03",
    "10.102.101.15": "hnn04",
}

# Excluded IPs (tidak terdeteksi sebagai port scan)
EXCLUDED_IPS = {
    "10.102.101.44",
}

# Mencegah duplikasi alert
SEEN = set()


def detect_port_scan(packet):
    if IP not in packet or TCP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    dport = packet[TCP].dport
    flags = packet[TCP].flags

    # Hanya deteksi SYN
    if flags != "S":
        return

    # Abaikan IP yang di-exclude
    if src in EXCLUDED_IPS:
        return

    # Cek apakah traffic menuju salah satu honeypot
    if src not in HONEYPOT_IPS and dst not in HONEYPOT_IPS:
        return

    # Tentukan nama honeypot
    honeypot_name = ""
    if dst in HONEYPOT_IPS:
        honeypot_name = HONEYPOT_IPS[dst]
    elif src in HONEYPOT_IPS:
        honeypot_name = HONEYPOT_IPS[src]

    # Cegah log ganda
    key = (src, dst, dport)
    if key in SEEN:
        return
    SEEN.add(key)

    print(f"Port scan detected from {src} to {dst} ({honeypot_name}), port {dport}")


print("Starting honeypot port scan detector...")
sniff(filter="tcp", prn=detect_port_scan, store=0)
