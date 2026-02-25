from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import os
import pandas as pd

from features.feature_extractor import extract_features

app = FastAPI()

# 🔥 CORS MUST BE AFTER app = FastAPI()
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