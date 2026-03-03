"""
MAD-CTI -- Main entry point.

Loads the sample dataset, runs the full pipeline, and saves results
to CSV and JSON in the output/ directory.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import os
from pathlib import Path

# Fix Windows console encoding for Unicode characters
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

import config
from logger import setup_logging
from pipeline import CTIPipeline


def load_dataset(path: Path) -> list[dict]:
    """Load documents from a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    print(f"[+] Loaded {len(data)} documents from {path.name}")
    return data


def save_json(results: list[dict], path: Path) -> None:
    """Save results to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[SAVE] Results saved to {path}")


def save_csv(results: list[dict], path: Path) -> None:
    """Save results to a CSV file."""
    if not results:
        return

    # Define the CSV columns (subset of most important fields)
    columns = [
        "id",
        "relevancy",
        "category",
        "confidence_score",
        "analysis_summary",
        "content_type",
        "original_language",
        "was_translated",
        "processing_time_seconds",
    ]

    # Add optional columns if present
    if "risk_score" in results[0]:
        columns.extend(["risk_score", "risk_level"])

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)
    print(f"[CSV] CSV saved to {path}")


def print_summary_table(results: list[dict]) -> None:
    """Print a formatted summary table to stdout."""
    print("\n" + "=" * 90)
    print(f"{'ID':<10} {'Relevancy':<15} {'Category':<15} {'Confidence':<12} {'Time (s)':<10}")
    print("-" * 90)
    for r in results:
        print(
            f"{r['id']:<10} "
            f"{r['relevancy']:<15} "
            f"{r['category']:<15} "
            f"{r['confidence_score']:<12.2f} "
            f"{r.get('processing_time_seconds', 0):<10.2f}"
        )
    print("=" * 90)

    # Stats
    relevant = sum(1 for r in results if r["relevancy"] == "Relevant")
    print(f"\n[STATS] Total: {len(results)} | Relevant: {relevant} | Not Relevant: {len(results) - relevant}")

    categories = {}
    for r in results:
        cat = r["category"]
        categories[cat] = categories.get(cat, 0) + 1
    print(f"[CATEGORIES] {dict(categories)}")

    if "risk_score" in results[0]:
        avg_risk = sum(r.get("risk_score", 0) for r in results) / len(results)
        print(f"[RISK] Average Risk Score: {avg_risk:.2f}")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MAD-CTI: Multi-Agent Cyber Threat Intelligence Analyzer"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=config.SAMPLE_DATASET_PATH,
        help="Path to input dataset JSON file",
    )
    parser.add_argument(
        "--risk-scoring",
        action="store_true",
        help="Enable the risk scoring agent (Phase 6)",
    )
    args = parser.parse_args()

    # -- Setup --
    print("\n=== MAD-CTI: Multi-Agent Cyber Threat Intelligence System ===")
    print("=" * 55)

    config.validate_config()
    log_file = setup_logging()
    print(f"[LOG] Logs -> {log_file}")

    # -- Load Data --
    documents = load_dataset(args.dataset)

    # -- Run Pipeline --
    pipeline = CTIPipeline(enable_risk_scoring=args.risk_scoring)
    results = pipeline.run_batch(documents)

    # -- Save Results --
    json_path = config.OUTPUT_DIR / "results.json"
    csv_path = config.OUTPUT_DIR / "results.csv"
    save_json(results, json_path)
    save_csv(results, csv_path)

    # -- Display Summary --
    print_summary_table(results)

    print("[DONE] Pipeline complete!")


if __name__ == "__main__":
    main()
