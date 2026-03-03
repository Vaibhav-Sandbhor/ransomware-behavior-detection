"""
Evaluation Module -- compares pipeline output against ground-truth labels.

Reports accuracy, precision, recall, and F1 per class, plus a confusion matrix.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

import config


def load_ground_truth(path: Path) -> list[dict]:
    """Load the dataset with ground-truth labels."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_predictions(path: Path) -> list[dict]:
    """Load the pipeline results."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def compute_metrics(
    y_true: list[str], y_pred: list[str], labels: list[str]
) -> dict:
    """
    Compute per-class precision, recall, F1, and overall accuracy.
    Pure Python — no sklearn dependency.
    """
    # Confusion counts per class
    metrics = {}
    for label in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == label and p == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != label and p == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == label and p != label)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        metrics[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(1 for t in y_true if t == label),
        }

    accuracy = sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)
    return {"per_class": metrics, "accuracy": round(accuracy, 4)}


def build_confusion_matrix(
    y_true: list[str], y_pred: list[str], labels: list[str]
) -> list[list[int]]:
    """Build a simple confusion matrix as a nested list."""
    label_to_idx = {label: i for i, label in enumerate(labels)}
    n = len(labels)
    matrix = [[0] * n for _ in range(n)]

    for t, p in zip(y_true, y_pred):
        ti = label_to_idx.get(t)
        pi = label_to_idx.get(p)
        if ti is not None and pi is not None:
            matrix[ti][pi] += 1

    return matrix


def print_confusion_matrix(matrix: list[list[int]], labels: list[str]) -> None:
    """Pretty-print a confusion matrix."""
    col_width = max(len(l) for l in labels) + 2

    # Header
    header = " " * col_width + "".join(l.center(col_width) for l in labels)
    print(header)
    print("-" * len(header))

    # Rows
    for i, label in enumerate(labels):
        row = label.ljust(col_width) + "".join(
            str(v).center(col_width) for v in matrix[i]
        )
        print(row)


def evaluate() -> None:
    """Run full evaluation pipeline."""
    print("\n[EVAL] MAD-CTI Evaluation Report")
    print("=" * 50)

    # Load data
    ground_truth = load_ground_truth(config.SAMPLE_DATASET_PATH)
    predictions_path = config.OUTPUT_DIR / "results.json"

    if not predictions_path.exists():
        print("[ERROR] No results found. Run main.py first.")
        return

    predictions = load_predictions(predictions_path)

    # Build lookup
    pred_by_id = {p["id"]: p for p in predictions}

    # ── Relevancy Evaluation ──────────────────────────────────────────
    print("\n[RELEVANCY] RELEVANCY CLASSIFICATION")
    print("-" * 40)

    rel_true = [d["ground_truth_relevancy"] for d in ground_truth]
    rel_pred = [pred_by_id[d["id"]]["relevancy"] for d in ground_truth]
    rel_labels = ["Relevant", "Not Relevant"]

    rel_metrics = compute_metrics(rel_true, rel_pred, rel_labels)
    print(f"  Accuracy: {rel_metrics['accuracy']:.2%}")
    for label, m in rel_metrics["per_class"].items():
        print(
            f"  {label:<15}  P={m['precision']:.2f}  R={m['recall']:.2f}  "
            f"F1={m['f1']:.2f}  (n={m['support']})"
        )

    print("\n  Confusion Matrix:")
    rel_cm = build_confusion_matrix(rel_true, rel_pred, rel_labels)
    print_confusion_matrix(rel_cm, rel_labels)

    # ── Category Evaluation ───────────────────────────────────────────
    print("\n\n[CATEGORY] CATEGORY CLASSIFICATION")
    print("-" * 40)

    cat_true = [d["ground_truth_category"] for d in ground_truth]
    cat_pred = [pred_by_id[d["id"]]["category"] for d in ground_truth]
    cat_labels = ["Hack", "Malware", "Vulnerability", "N/A"]

    cat_metrics = compute_metrics(cat_true, cat_pred, cat_labels)
    print(f"  Accuracy: {cat_metrics['accuracy']:.2%}")
    for label, m in cat_metrics["per_class"].items():
        print(
            f"  {label:<15}  P={m['precision']:.2f}  R={m['recall']:.2f}  "
            f"F1={m['f1']:.2f}  (n={m['support']})"
        )

    print("\n  Confusion Matrix:")
    cat_cm = build_confusion_matrix(cat_true, cat_pred, cat_labels)
    print_confusion_matrix(cat_cm, cat_labels)

    # ── Summary ───────────────────────────────────────────────────────
    print("\n\n[SUMMARY] OVERALL SUMMARY")
    print("-" * 40)
    print(f"  Relevancy Accuracy: {rel_metrics['accuracy']:.2%}")
    print(f"  Category Accuracy:  {cat_metrics['accuracy']:.2%}")

    # Per-document detail
    print("\n[DETAIL] PER-DOCUMENT RESULTS")
    print(f"{'ID':<10} {'Rel(GT)':<15} {'Rel(Pred)':<15} {'Cat(GT)':<15} {'Cat(Pred)':<15} {'Match'}")
    print("-" * 85)
    for d in ground_truth:
        did = d["id"]
        p = pred_by_id[did]
        rel_match = d["ground_truth_relevancy"] == p["relevancy"]
        cat_match = d["ground_truth_category"] == p["category"]
        match_icon = "PASS" if (rel_match and cat_match) else "FAIL"
        print(
            f"{did:<10} "
            f"{d['ground_truth_relevancy']:<15} "
            f"{p['relevancy']:<15} "
            f"{d['ground_truth_category']:<15} "
            f"{p['category']:<15} "
            f"{match_icon}"
        )

    print("\n[DONE] Evaluation complete!\n")


if __name__ == "__main__":
    evaluate()
