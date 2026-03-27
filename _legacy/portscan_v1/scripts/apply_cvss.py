import csv
import sys
from data.cvss_rules import CVSS_RULES

INPUT_FILE = "data/portscan_dataset.csv"
OUTPUT_FILE = "data/portscan_dataset.csv"

rows = []

with open(INPUT_FILE, newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        service = row.get("service", "").lower()
        row["cvss"] = CVSS_RULES.get(service, 3.0)
        rows.append(row)

# ---------- SAFETY CHECK ----------
if not rows:
    print("[!] No open services found — CVSS not applied")
    sys.exit(0)
# ----------------------------------

with open(OUTPUT_FILE, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print("[+] CVSS values applied successfully")

