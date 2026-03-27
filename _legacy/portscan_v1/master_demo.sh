#!/bin/bash

set -e

echo "[*] Activating virtual environment..."
source venv/bin/activate

echo "[*] Running Nmap scan with Vulners..."
nmap -Pn -sT -sV -T4 \
-p21,22,23,25,53,80,110,139,445,3306,8080 \
-oX scan.xml 192.168.254.130

echo "[*] Parsing Nmap + Vulners output..."
python parser/parse_nmap_vulners.py

echo "[*] Applying CVSS rules..."
python -m scripts.apply_cvss

echo "[*] Running ML risk prediction..."
python -m scripts.predict_risk

echo "[+] DONE — Risk analysis completed"

