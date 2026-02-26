"""
monte_carlo_validation.py
==========================
Module 11: Monte Carlo Validation Harness

Executes large-scale randomized simulations of the full ransomware detection
pipeline (honeypot scoring + LSTM inference) and reports:

  * Honeypot-layer confusion matrix and metrics
  * ML-layer metrics (when LSTM model is available)
  * Combined two-layer system metrics
  * Detection latency distribution
  * False-positive / false-negative analysis
  * Confidence-score statistics

The harness simulates both benign and ransomware process episodes from scratch
without touching the real filesystem, making it safe to run in CI.

Expected targets (from MASTER PROMPT ?11):
    Accuracy  > 0.95
    Recall    > 0.95 (TPR)
    FPR       ~ 0.00

Usage:
    python -m ransomware_module.tests.monte_carlo_validation
    python -m ransomware_module.tests.monte_carlo_validation \\
        --benign 1000 --ransom 1000 --seed 42
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent.parent   # CyberSIEM/
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_MODULE_ROOT = _ROOT / "ransomware_module"

from ransomware_module.utils.feature_extractor import (
    BEHAVIORAL_FEATURES,
    classify_threat,
    threat_to_alert_level,
    validate_feature_row,
)

# ---------------------------------------------------------------------------
# Lazy ML loader
# ---------------------------------------------------------------------------

def _try_load_detector(threshold: float = 0.70):
    """Return a RansomwareDetector or None if model/TF not available."""
    try:
        from ransomware_module.models.predict_lstm import RansomwareDetector
        det = RansomwareDetector(threshold=threshold)
        det._ensure_loaded()
        return det
    except Exception as exc:
        print(f"[MC] LSTM unavailable ({exc}) -- running heuristic-only mode.")
        return None


# ---------------------------------------------------------------------------
# Heuristic scoring (mirrors realtime_csv_monitor)
# ---------------------------------------------------------------------------

def _heuristic_score(row: Dict) -> float:
    score = 0.0
    entropy = float(row.get("entropy", 0) or 0)
    ext_ch  = int(row.get("extension_change", 0) or 0)
    writes  = int(row.get("file_write_count", 0) or 0)
    deletes = int(row.get("file_delete_count", 0) or 0)
    renames = int(row.get("registry_change_count", 0) or 0)
    cpu     = float(row.get("cpu_usage", 0) or 0)

    if entropy > 7.0:    score += 0.35
    elif entropy > 6.0:  score += 0.20
    elif entropy > 4.5:  score += 0.08
    if ext_ch:           score += 0.25
    if writes > 20:      score += 0.20
    elif writes > 10:    score += 0.10
    elif writes > 5:     score += 0.05
    if deletes > 5:      score += 0.10
    elif deletes > 2:    score += 0.05
    if renames > 3:      score += 0.10
    if cpu > 70:         score += 0.10
    return round(min(score, 1.0), 4)


# ---------------------------------------------------------------------------
# Episode generators
# ---------------------------------------------------------------------------

def _clip(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def generate_benign_episode(rng) -> Dict:
    """Sample a single benign feature row."""
    return {
        "cpu_usage":             round(rng.uniform(1, 25), 2),
        "memory_usage":          round(rng.uniform(30, 200), 2),
        "file_read_count":       max(0, int(rng.poisson(5))),
        "file_write_count":      max(0, int(rng.poisson(2))),
        "file_delete_count":     max(0, int(rng.poisson(0.2))),
        "registry_change_count": max(0, int(rng.poisson(0.5))),
        "network_connections":   max(0, int(rng.poisson(2))),
        "entropy":               round(_clip(rng.normal(2.5, 1.0), 0, 5), 4),
        "extension_change":      int(rng.random() < 0.02),
        "process_spawn_count":   max(0, int(rng.poisson(0.5))),
    }


def generate_ransomware_episode(rng) -> Dict:
    """Sample a single ransomware feature row."""
    return {
        "cpu_usage":             round(rng.uniform(30, 90), 2),
        "memory_usage":          round(rng.uniform(80, 400), 2),
        "file_read_count":       max(0, int(rng.poisson(8))),
        "file_write_count":      max(5, int(rng.poisson(25))),
        "file_delete_count":     max(0, int(rng.poisson(5))),
        "registry_change_count": max(0, int(rng.poisson(4))),
        "network_connections":   max(0, int(rng.poisson(1))),
        "entropy":               round(_clip(rng.normal(7.4, 0.4), 6, 8), 4),
        "extension_change":      int(rng.random() < 0.92),
        "process_spawn_count":   max(0, int(rng.poisson(2))),
    }


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class MCResult:
    true_label:       int      # 0=benign, 1=ransomware
    heuristic_score:  float
    heuristic_alert:  bool
    ml_prob:          Optional[float]
    ml_alert:         Optional[bool]
    combined_alert:   bool     # True if EITHER layer fires
    latency_ms:       Optional[float]


# ---------------------------------------------------------------------------
# Single-episode evaluation
# ---------------------------------------------------------------------------

def _evaluate_episode(
    row: Dict,
    true_label: int,
    detector,
    threshold: float,
    heuristic_threshold: float,
) -> MCResult:
    t0 = time.perf_counter()

    # Honeypot heuristic layer
    h_score = _heuristic_score(row)
    h_alert = h_score >= heuristic_threshold

    # ML layer
    ml_prob = ml_alert = None
    if detector is not None:
        try:
            result  = detector.predict_dict(row)
            ml_prob = result["confidence"]
            ml_alert = ml_prob >= threshold
        except Exception:
            pass

    latency_ms = (time.perf_counter() - t0) * 1000

    # Combined: alert if either layer fires
    if ml_alert is not None:
        combined = h_alert or ml_alert
    else:
        combined = h_alert

    return MCResult(
        true_label=true_label,
        heuristic_score=h_score,
        heuristic_alert=h_alert,
        ml_prob=ml_prob,
        ml_alert=ml_alert,
        combined_alert=combined,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

@dataclass
class LayerMetrics:
    layer:    str
    tp: int; tn: int; fp: int; fn: int
    accuracy: float; precision: float; recall: float
    f1: float; fpr: float

    @classmethod
    def compute(cls, layer: str, results: List[MCResult], use_combined: bool = False) -> "LayerMetrics":
        tp = tn = fp = fn = 0
        for r in results:
            if use_combined:
                pred = int(r.combined_alert)
            elif layer == "heuristic":
                pred = int(r.heuristic_alert)
            else:
                if r.ml_alert is None:
                    continue
                pred = int(r.ml_alert)
            true = r.true_label
            if pred == 1 and true == 1: tp += 1
            elif pred == 0 and true == 0: tn += 1
            elif pred == 1 and true == 0: fp += 1
            else: fn += 1
        total = tp + tn + fp + fn
        acc   = (tp + tn) / total if total else 0.0
        prec  = tp / (tp + fp)   if (tp + fp) else 0.0
        rec   = tp / (tp + fn)   if (tp + fn) else 0.0
        f1    = 2*prec*rec / (prec+rec) if (prec+rec) else 0.0
        fpr   = fp / (fp + tn)   if (fp + tn) else 0.0
        return cls(layer=layer, tp=tp, tn=tn, fp=fp, fn=fn,
                   accuracy=round(acc,4), precision=round(prec,4),
                   recall=round(rec,4), f1=round(f1,4), fpr=round(fpr,4))

    def print(self) -> None:
        print(f"\n  [{self.layer.upper()}]")
        print(f"    TP={self.tp}  TN={self.tn}  FP={self.fp}  FN={self.fn}")
        print(f"    Accuracy  : {self.accuracy:.4f}  {'OK' if self.accuracy>=0.95 else 'FAIL (target >0.95)'}")
        print(f"    Precision : {self.precision:.4f}")
        print(f"    Recall    : {self.recall:.4f}  {'OK' if self.recall>=0.95 else 'FAIL (target >0.95)'}")
        print(f"    F1        : {self.f1:.4f}")
        print(f"    FPR       : {self.fpr:.4f}  {'OK' if self.fpr<=0.05 else 'FAIL (target ~0.00)'}")


# ---------------------------------------------------------------------------
# Main Monte Carlo runner
# ---------------------------------------------------------------------------

def run_monte_carlo(
    n_benign: int       = 500,
    n_ransom: int       = 500,
    seed: Optional[int] = None,
    threshold: float    = 0.70,
    heuristic_threshold: float = 0.50,
    verbose: bool       = True,
) -> Dict:
    """
    Run Monte Carlo simulation and print/return full metrics report.

    Returns
    -------
    dict with keys: heuristic_metrics, ml_metrics (or None), combined_metrics,
                    latency_stats, score_stats, fn_samples, fp_samples
    """
    rng_seed = seed if seed is not None else int(time.time())
    rng = np.random.default_rng(rng_seed)
    random.seed(rng_seed)

    print(f"\n{'='*65}")
    print("  CyberSIEM Monte Carlo Validation -- Ransomware Detection System")
    print(f"{'='*65}")
    print(f"  Benign episodes   : {n_benign}")
    print(f"  Ransomware episodes: {n_ransom}")
    print(f"  Seed              : {rng_seed}")
    print(f"  LSTM threshold    : {threshold}")
    print(f"  Heuristic thr     : {heuristic_threshold}")
    print(f"{'='*65}\n")

    # Load LSTM detector once
    detector = _try_load_detector(threshold)

    results: List[MCResult] = []

    # -- Generate benign episodes ------------------------------------------
    if verbose:
        print(f"[MC] Simulating {n_benign} benign episodes...")
    for _ in range(n_benign):
        row = generate_benign_episode(rng)
        r   = _evaluate_episode(row, 0, detector, threshold, heuristic_threshold)
        results.append(r)

    # -- Generate ransomware episodes --------------------------------------
    if verbose:
        print(f"[MC] Simulating {n_ransom} ransomware episodes...")
    for _ in range(n_ransom):
        row = generate_ransomware_episode(rng)
        r   = _evaluate_episode(row, 1, detector, threshold, heuristic_threshold)
        results.append(r)

    # -- Metrics -------------------------------------------------------------
    h_metrics   = LayerMetrics.compute("heuristic", results)
    combined_m  = LayerMetrics.compute("combined",  results, use_combined=True)
    ml_metrics  = None
    if detector is not None:
        ml_metrics = LayerMetrics.compute("lstm", results)

    # -- Score / confidence distributions ------------------------------------
    h_benign_scores  = [r.heuristic_score for r in results if r.true_label == 0]
    h_ransom_scores  = [r.heuristic_score for r in results if r.true_label == 1]

    # -- Latency -------------------------------------------------------------
    latencies = [r.latency_ms for r in results if r.latency_ms is not None]

    # -- False-negative / false-positive samples --------------------------
    fn_samples = [r for r in results if r.true_label == 1 and not r.combined_alert][:5]
    fp_samples = [r for r in results if r.true_label == 0 and r.combined_alert][:5]

    # -- Print report -----------------------------------------------------
    print("\n--- Layer Metrics -------------------------------------------")
    h_metrics.print()
    if ml_metrics:
        ml_metrics.print()
    combined_m.print()

    print("\n--- Score Distributions (heuristic) ------------------------")
    if h_benign_scores:
        print(f"  Benign   mean={statistics.mean(h_benign_scores):.4f}  "
              f"max={max(h_benign_scores):.4f}")
    if h_ransom_scores:
        print(f"  Ransom   mean={statistics.mean(h_ransom_scores):.4f}  "
              f"min={min(h_ransom_scores):.4f}")

    if ml_metrics and detector:
        ml_benign  = [r.ml_prob for r in results if r.true_label==0 and r.ml_prob is not None]
        ml_ransom  = [r.ml_prob for r in results if r.true_label==1 and r.ml_prob is not None]
        print("\n--- ML Confidence Distributions -------------------------")
        if ml_benign:
            print(f"  Benign   mean={statistics.mean(ml_benign):.4f}  "
                  f"max={max(ml_benign):.4f}")
        if ml_ransom:
            print(f"  Ransom   mean={statistics.mean(ml_ransom):.4f}  "
                  f"min={min(ml_ransom):.4f}")

    print("\n--- Latency (per-row inference) -----------------------------")
    if latencies:
        print(f"  Mean    : {statistics.mean(latencies):.3f} ms")
        print(f"  Median  : {statistics.median(latencies):.3f} ms")
        p99 = sorted(latencies)[int(0.99 * len(latencies))]
        print(f"  p99     : {p99:.3f} ms")

    if fn_samples:
        print(f"\n--- False-Negative Samples (first {len(fn_samples)}) ------")
        for r in fn_samples:
            print(f"  h_score={r.heuristic_score:.4f}  "
                  f"ml_prob={r.ml_prob if r.ml_prob is not None else 'N/A'}")

    if fp_samples:
        print(f"\n--- False-Positive Samples (first {len(fp_samples)}) ------")
        for r in fp_samples:
            print(f"  h_score={r.heuristic_score:.4f}  "
                  f"ml_prob={r.ml_prob if r.ml_prob is not None else 'N/A'}")

    print("\n--- Overall System Assessment -------------------------------")
    passed = []
    failed = []
    for chk, ok in [
        (f"Accuracy  >= 0.95  (got {combined_m.accuracy:.4f})", combined_m.accuracy >= 0.95),
        (f"Recall    >= 0.95  (got {combined_m.recall:.4f})",   combined_m.recall   >= 0.95),
        (f"FPR       <= 0.05  (got {combined_m.fpr:.4f})",      combined_m.fpr      <= 0.05),
    ]:
        (passed if ok else failed).append(chk)

    for c in passed:
        print(f"  PASS  {c}")
    for c in failed:
        print(f"  FAIL  {c}")

    status = "PASS" if not failed else "FAIL"
    print(f"\n  Overall: {status}\n{'='*65}\n")

    return {
        "heuristic_metrics": h_metrics,
        "ml_metrics":        ml_metrics,
        "combined_metrics":  combined_m,
        "latency_stats":     latencies,
        "fn_samples":        fn_samples,
        "fp_samples":        fp_samples,
        "status":            status,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CyberSIEM Monte Carlo Ransomware Detection Validator"
    )
    p.add_argument("--benign",   type=int,   default=500)
    p.add_argument("--ransom",   type=int,   default=500)
    p.add_argument("--seed",     type=int,   default=None)
    p.add_argument("--threshold",type=float, default=0.70,
                   help="LSTM decision threshold (default: 0.70)")
    p.add_argument("--heuristic-threshold", type=float, default=0.50,
                   help="honeypot heuristic trigger threshold (default: 0.50)")
    p.add_argument("--quiet",    action="store_true",
                   help="suppress per-episode progress messages")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    run_monte_carlo(
        n_benign=args.benign,
        n_ransom=args.ransom,
        seed=args.seed,
        threshold=args.threshold,
        heuristic_threshold=args.heuristic_threshold,
        verbose=not args.quiet,
    )


if __name__ == "__main__":
    main()
