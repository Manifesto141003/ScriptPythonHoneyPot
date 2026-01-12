#!/usr/bin/env python3
import os
from pathlib import Path
from datetime import datetime
import glob

# ============================================================
# CONFIG
# ============================================================
BASE_DIR = Path("/var/www/html/blacklist")
DAILY_DIR = BASE_DIR / "daily"
WEEKLY_DIR = BASE_DIR / "weekly"
MONTHLY_DIR = BASE_DIR / "monthly"

DAILY_DIR.mkdir(parents=True, exist_ok=True)
WEEKLY_DIR.mkdir(parents=True, exist_ok=True)
MONTHLY_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# HELPERS
# ============================================================

def read_file(path):
    if not Path(path).exists():
        return []
    with open(path, "r") as f:
        return f.readlines()

def write_file(path, lines):
    with open(path, "w") as f:
        f.writelines(lines)

def append_file(path, lines):
    with open(path, "a") as f:
        f.writelines(lines)

# ============================================================
# DAILY → WEEKLY
# ============================================================

def rotate_daily_to_weekly():
    daily_files = sorted(glob.glob(f"{DAILY_DIR}/daily_*.txt"))

    # Butuh minimal 7 file
    if len(daily_files) < 7:
        return

    # Ambil 7 file pertama
    block = daily_files[:7]

    # Extract tanggal dari nama file
    first_date = block[0].split("_")[-1].replace(".txt", "")
    last_date = block[-1].split("_")[-1].replace(".txt", "")

    weekly_name = f"weekly_{first_date}_to_{last_date}.txt"
    weekly_path = WEEKLY_DIR / weekly_name

    weekly_content = []

    for f in block:
        filename = os.path.basename(f)
        weekly_content.append(f"--- {filename} ---\n")
        weekly_content.extend(read_file(f))
        weekly_content.append("\n")

    write_file(weekly_path, weekly_content)

    # Hapus 7 file daily
    for f in block:
        os.remove(f)


# ============================================================
# WEEKLY → MONTHLY
# ============================================================

def rotate_weekly_to_monthly():
    weekly_files = sorted(glob.glob(f"{WEEKLY_DIR}/weekly_*.txt"))

    if len(weekly_files) < 4:
        return

    block = weekly_files[:4]

    # Extract tanggal dari nama file weekly
    first_date = block[0].split("_")[1]
    last_date = block[-1].split("_")[-1].replace(".txt", "")

    monthly_name = f"monthly_{first_date}_to_{last_date}.txt"
    monthly_path = MONTHLY_DIR / monthly_name

    monthly_content = []

    for f in block:
        filename = os.path.basename(f)
        monthly_content.append(f"===== {filename} =====\n")
        monthly_content.extend(read_file(f))
        monthly_content.append("\n")

    write_file(monthly_path, monthly_content)

    # Hapus weekly
    for f in block:
        os.remove(f)


# ============================================================
# ENSURE DAILY FILE EXISTS (EMPTY IF NO DETECTION)
# ============================================================

def ensure_today_daily_file():
    today = datetime.now().strftime("%Y-%m-%d")
    today_file = DAILY_DIR / f"daily_{today}.txt"

    if not today_file.exists():
        write_file(today_file, ["# No detections for this day\n"])


# ============================================================
# MAIN
# ============================================================

def main():
    ensure_today_daily_file()      # Pastikan file hari ini ada
    rotate_daily_to_weekly()       # Convert 7 daily → 1 weekly
    rotate_weekly_to_monthly()     # Convert 4 weekly → 1 monthly


if __name__ == "__main__":
    main()
