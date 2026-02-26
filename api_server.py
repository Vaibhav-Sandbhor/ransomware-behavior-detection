from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import os
import pandas as pd
import csv
import sys
import subprocess
from pathlib import Path

from features.feature_extractor import extract_features

# ---------------------------------------------------------------------------
# Ransomware module output paths
# ---------------------------------------------------------------------------
_RANSOM_ROOT     = Path(__file__).parent / "ransomware_module"
_PREDICTIONS_LOG = _RANSOM_ROOT / "output" / "predictions_log.csv"
_ALERTS_LOG      = _RANSOM_ROOT / "output" / "alerts.log"
_HONEYPOT_LOG    = _RANSOM_ROOT / "honeypot" / "honeypot_log.csv"

app = FastAPI()

# CORS - must be after app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = os.path.join("models", "rf_model.joblib")
model = joblib.load(MODEL_PATH)

WINDOW_SIZE = 25

class ScanInput(BaseModel):
    sample_path: str
    label: int = 0

@app.post("/scan")
def scan(data: ScanInput):

    print("Received request")
    print("Sample path:", data.sample_path)

    df = extract_features(data.sample_path, data.label)

    print("Extracted features")

    if df is None:
        return {"error": "Feature extraction failed"}

    numeric_cols = [
        "ata_entropy_avg",
        "mem_entropy_avg",
        "disk_write_ratio",
        "mem_write_ratio"
    ]

    df = df[numeric_cols]
    df_window = df.iloc[:WINDOW_SIZE]
    features = df_window.to_numpy().flatten()

    if len(features) != 100:
        return {"error": f"Expected 100 features, got {len(features)}"}

    features = features.reshape(1, -1)
    prediction = model.predict(features)[0]
    probability = float(model.predict_proba(features)[0][1])

    return {
    "prediction": int(prediction),
    "status": "Malicious" if prediction == 1 else "Safe",
    "probability": round(probability, 4)
}


# ---------------------------------------------------------------------------
# Ransomware Module Pipeline Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/ransomware/run-pipeline")
def run_ransomware_pipeline():
    """
    Run the full 3-step ransomware detection pipeline inline (no subprocesses).
    Step 1: Simulate honeypot -> honeypot_log.csv
    Step 2: Extract features  -> live_input.csv
    Step 3: Run ML predictions -> predictions_log.csv + alerts.log
    """
    # Ensure ransomware_module is importable from this directory
    _root = str(Path(__file__).parent)
    if _root not in sys.path:
        sys.path.insert(0, _root)

    try:
        # ── Step 1: Simulate ──────────────────────────────────────────────
        from ransomware_module.honeypot.honeypot_simulator import run_simulation
        run_simulation(n_benign=50, n_ransom_bursts=5, seed=42)

        # ── Step 2: Extract features ──────────────────────────────────────
        from ransomware_module.utils.honeypot_feature_extractor import extract
        extract()

        # ── Step 3: Predict inline ────────────────────────────────────────
        from ransomware_module.models.predict_lstm import RansomwareDetector
        from datetime import datetime

        det = RansomwareDetector(threshold=0.5)
        det._ensure_loaded()

        live_input = _RANSOM_ROOT / "data" / "live_input.csv"
        _PREDICTIONS_LOG.parent.mkdir(parents=True, exist_ok=True)

        predictions = []
        alerts_text = ""

        with open(live_input, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                result  = det.predict_dict(row)
                ts      = row.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                proc    = row.get("process_name", "unknown")
                conf    = round(float(result["confidence"]), 4)
                threat  = result["threat_level"]
                pred    = result["prediction"]

                predictions.append({
                    "timestamp":    ts,
                    "process_name": proc,
                    "prediction":   pred,
                    "confidence":   conf,
                    "threat_level": threat,
                    "source":       "LSTM+HONEYPOT",
                })

                if threat in ("WARNING", "CRITICAL"):
                    label = "ransomware" if threat == "CRITICAL" else "suspicious"
                    alerts_text += "=" * 60 + "\n"
                    alerts_text += f"{threat} ALERT\n"
                    alerts_text += f"Timestamp  : {ts}\n"
                    alerts_text += f"Detection  : Early {label} detected\n"
                    alerts_text += f"Process    : {proc}\n"
                    alerts_text += f"Confidence : {conf}\n"
                    alerts_text += f"Source     : LSTM+HONEYPOT\n"
                    alerts_text += "=" * 60 + "\n\n"

        # Write predictions_log.csv
        with open(_PREDICTIONS_LOG, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "process_name", "prediction",
                "confidence", "threat_level", "source"
            ])
            writer.writeheader()
            writer.writerows(predictions)

        # Write alerts.log
        with open(_ALERTS_LOG, "w", encoding="utf-8") as f:
            f.write(alerts_text)

        summary = {
            "total":      len(predictions),
            "benign":     sum(1 for p in predictions if p["threat_level"] == "INFO"),
            "suspicious": sum(1 for p in predictions if p["threat_level"] == "WARNING"),
            "ransomware": sum(1 for p in predictions if p["threat_level"] == "CRITICAL"),
        }
        return {"status": "ok", "message": "Pipeline completed successfully", "summary": summary}

    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "detail": traceback.format_exc()}


@app.get("/api/ransomware/predictions")
def get_ransomware_predictions():
    """Return predictions_log.csv as a JSON list with summary stats."""
    if not _PREDICTIONS_LOG.exists():
        return {
            "predictions": [],
            "summary": {"total": 0, "benign": 0, "suspicious": 0, "ransomware": 0}
        }

    rows = []
    with open(_PREDICTIONS_LOG, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append({
                "timestamp":   row.get("timestamp", ""),
                "process":     row.get("process_name", ""),
                "prediction":  row.get("prediction", ""),
                "confidence":  float(row.get("confidence", 0)),
                "threatLevel": row.get("threat_level", "INFO"),
                "source":      row.get("source", ""),
            })

    summary = {
        "total":      len(rows),
        "benign":     sum(1 for r in rows if r["threatLevel"] == "INFO"),
        "suspicious": sum(1 for r in rows if r["threatLevel"] == "WARNING"),
        "ransomware": sum(1 for r in rows if r["threatLevel"] == "CRITICAL"),
    }
    return {"predictions": rows, "summary": summary}


@app.get("/api/ransomware/alerts")
def get_ransomware_alerts():
    """Return alerts.log parsed into a JSON list."""
    if not _ALERTS_LOG.exists():
        return {"alerts": []}

    with open(_ALERTS_LOG, "r", encoding="utf-8") as f:
        content = f.read()

    alerts = []
    for block in content.split("=" * 60):
        block = block.strip()
        if not block:
            continue
        alert = {}
        for line in (l.strip() for l in block.splitlines() if l.strip()):
            if line in ("CRITICAL ALERT", "WARNING ALERT"):
                alert["level"] = line.replace(" ALERT", "")
            elif line.startswith("Timestamp"):
                alert["timestamp"] = line.split(":", 1)[1].strip()
            elif line.startswith("Detection"):
                alert["detection"] = line.split(":", 1)[1].strip()
            elif line.startswith("Process"):
                alert["process"] = line.split(":", 1)[1].strip()
            elif line.startswith("Confidence"):
                try:
                    alert["confidence"] = float(line.split(":", 1)[1].strip())
                except ValueError:
                    alert["confidence"] = 0.0
            elif line.startswith("Source"):
                alert["source"] = line.split(":", 1)[1].strip()
        if alert.get("level"):
            alerts.append(alert)

    return {"alerts": alerts}


@app.get("/api/honeypot/log")
def get_honeypot_log():
    """Return honeypot_log.csv as a JSON list with summary stats."""
    if not _HONEYPOT_LOG.exists():
        return {
            "events": [],
            "summary": {"total": 0, "critical": 0, "warning": 0, "benign": 0},
        }

    rows = []
    with open(_HONEYPOT_LOG, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                score = float(row.get("suspicious_score", 0))
            except ValueError:
                score = 0.0
            rows.append({
                "timestamp":        row.get("timestamp", ""),
                "process":          row.get("process_name", ""),
                "filePath":         row.get("file_path", ""),
                "operation":        row.get("operation", ""),
                "entropy":          round(float(row.get("entropy", 0) or 0), 4),
                "extensionChanged": int(row.get("extension_changed", 0) or 0),
                "writeCount":       int(row.get("write_count", 0) or 0),
                "renameCount":      int(row.get("rename_count", 0) or 0),
                "suspiciousScore":  round(score, 4),
                "level": (
                    "CRITICAL" if score >= 0.7 else
                    "WARNING"  if score >= 0.4 else
                    "INFO"
                ),
            })

    summary = {
        "total":    len(rows),
        "critical": sum(1 for r in rows if r["level"] == "CRITICAL"),
        "warning":  sum(1 for r in rows if r["level"] == "WARNING"),
        "benign":   sum(1 for r in rows if r["level"] == "INFO"),
    }
    return {"events": rows, "summary": summary}
