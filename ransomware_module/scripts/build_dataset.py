"""
build_dataset.py
================
Generate synthetic behavioral training data for the ransomware_module LSTM.

Produces a CSV at  ransomware_module/data/training_data.csv  with realistic
feature distributions for benign and ransomware processes.

Behavioral feature distributions
---------------------------------
BENIGN processes (label=0):
    cpu_usage          ~ Uniform(1, 25)
    memory_usage       ~ Uniform(30, 200)
    file_read_count    ~ Poisson(5, clip 0..30)
    file_write_count   ~ Poisson(2, clip 0..8)
    file_delete_count  ~ Poisson(0.2, clip 0..3)
    registry_change_count ~ Poisson(0.5, clip 0..3)
    network_connections   ~ Poisson(2, clip 0..10)
    entropy            ~ Normal(2.5, 1.0, clip 0..5)
    extension_change   ~ Bernoulli(0.02)
    process_spawn_count   ~ Poisson(0.5, clip 0..4)

RANSOMWARE processes (label=1):
    cpu_usage          ~ Uniform(30, 90)
    memory_usage       ~ Uniform(80, 400)
    file_read_count    ~ Poisson(8, clip 0..30)
    file_write_count   ~ Poisson(25, clip 5..60)
    file_delete_count  ~ Poisson(5, clip 0..20)
    registry_change_count ~ Poisson(4, clip 0..10)
    network_connections   ~ Poisson(1, clip 0..6)
    entropy            ~ Normal(7.4, 0.4, clip 6..8)
    extension_change   ~ Bernoulli(0.92)
    process_spawn_count   ~ Poisson(2, clip 0..8)

Usage:
    python -m ransomware_module.scripts.build_dataset
    python -m ransomware_module.scripts.build_dataset --samples 5000 --seed 42
"""

from __future__ import annotations

import argparse
import csv
import os
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict

import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_MODULE_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR    = _MODULE_ROOT / "data"
DEFAULT_OUTPUT = _DATA_DIR / "training_data.csv"

HEADER = [
    "timestamp", "process_name",
    "cpu_usage", "memory_usage",
    "file_read_count", "file_write_count", "file_delete_count",
    "registry_change_count", "network_connections",
    "entropy", "extension_change", "process_spawn_count",
    "label",
]

# ---------------------------------------------------------------------------
# Process name pools
# ---------------------------------------------------------------------------
_BENIGN_PROCS = [
    "explorer.exe", "chrome.exe", "winword.exe", "excel.exe", "teams.exe",
    "outlook.exe", "notepad.exe", "powerpnt.exe", "acrobat.exe", "slack.exe",
    "firefox.exe", "code.exe", "cmd.exe", "powershell.exe", "svchost.exe",
]

_RANSOM_PROCS = [
    "svc_update32.exe", "taskhost_helper.exe", "conhost_srv.exe",
    "wmiprvse_helper.exe", "syswow64svc.exe", "wscript_svc.exe",
    "rundll32_helper.exe", "csrss_svc.exe", "lsass_helper.exe",
    "winlogon_svc.exe",
]


# ---------------------------------------------------------------------------
# Sample generators
# ---------------------------------------------------------------------------

def _ts(base: datetime, i: int) -> str:
    return (base + timedelta(seconds=i * 10)).strftime("%Y-%m-%d %H:%M:%S")


def _clip_int(value: float, lo: int, hi: int) -> int:
    return int(max(lo, min(hi, round(value))))


def generate_benign_sample(base_ts: datetime, idx: int, rng: np.random.Generator) -> Dict:
    proc = _BENIGN_PROCS[idx % len(_BENIGN_PROCS)]
    return {
        "timestamp":            _ts(base_ts, idx),
        "process_name":         proc,
        "cpu_usage":            round(float(rng.uniform(1, 25)), 2),
        "memory_usage":         round(float(rng.uniform(30, 200)), 2),
        "file_read_count":      _clip_int(rng.poisson(5),   0, 30),
        "file_write_count":     _clip_int(rng.poisson(2),   0,  8),
        "file_delete_count":    _clip_int(rng.poisson(0.2), 0,  3),
        "registry_change_count":_clip_int(rng.poisson(0.5), 0,  3),
        "network_connections":  _clip_int(rng.poisson(2),   0, 10),
        "entropy":              round(float(np.clip(rng.normal(2.5, 1.0), 0, 5)), 4),
        "extension_change":     int(rng.random() < 0.02),
        "process_spawn_count":  _clip_int(rng.poisson(0.5), 0,  4),
        "label": 0,
    }


def generate_ransomware_sample(base_ts: datetime, idx: int, rng: np.random.Generator) -> Dict:
    proc = _RANSOM_PROCS[idx % len(_RANSOM_PROCS)]
    return {
        "timestamp":            _ts(base_ts, idx),
        "process_name":         proc,
        "cpu_usage":            round(float(rng.uniform(30, 90)), 2),
        "memory_usage":         round(float(rng.uniform(80, 400)), 2),
        "file_read_count":      _clip_int(rng.poisson(8),  0, 30),
        "file_write_count":     _clip_int(rng.poisson(25), 5, 60),
        "file_delete_count":    _clip_int(rng.poisson(5),  0, 20),
        "registry_change_count":_clip_int(rng.poisson(4),  0, 10),
        "network_connections":  _clip_int(rng.poisson(1),  0,  6),
        "entropy":              round(float(np.clip(rng.normal(7.4, 0.4), 6, 8)), 4),
        "extension_change":     int(rng.random() < 0.92),
        "process_spawn_count":  _clip_int(rng.poisson(2),  0,  8),
        "label": 1,
    }


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_dataset(
    n_benign: int   = 3000,
    n_ransom: int   = 3000,
    output: Path    = DEFAULT_OUTPUT,
    seed: int       = 42,
    shuffle: bool   = True,
) -> Path:
    """
    Generate a balanced synthetic training dataset and write it to *output*.

    Returns the output path.
    """
    rng = np.random.default_rng(seed)
    base_ts = datetime(2026, 1, 1, 8, 0, 0)

    rows: List[Dict] = []
    print(f"[DATASET] Generating {n_benign} benign samples…")
    for i in range(n_benign):
        rows.append(generate_benign_sample(base_ts, i, rng))

    print(f"[DATASET] Generating {n_ransom} ransomware samples…")
    for i in range(n_ransom):
        rows.append(generate_ransomware_sample(base_ts, n_benign + i, rng))

    if shuffle:
        rng.shuffle(rows)  # type: ignore[arg-type]

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)

    total = n_benign + n_ransom
    print(f"[DATASET] Wrote {total} rows ({n_benign} benign, {n_ransom} ransomware) -> {output}")
    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generate synthetic ransomware behavioral dataset")
    p.add_argument("--samples", type=int, default=3000,
                   help="samples per class (default: 3000 each = 6000 total)")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                   help="output CSV path")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-shuffle", action="store_true")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    build_dataset(
        n_benign=args.samples,
        n_ransom=args.samples,
        output=args.output,
        seed=args.seed,
        shuffle=not args.no_shuffle,
    )


if __name__ == "__main__":
    main()
