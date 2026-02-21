import os
import numpy as np
import pandas as pd
import argparse
import joblib
from tensorflow.keras.models import load_model

# compute project root so relative paths work from anywhere
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_MODEL_PATH = os.path.join(ROOT, "models", "lstm_model.keras")
DEFAULT_SCALER_PATH = os.path.join(ROOT, "models", "scaler.pkl")
DEFAULT_DATA_PATH = os.path.join(ROOT, "data", "processed", "ransomware_features.csv")


def load_detector(model_path=None, scaler_path=None):
    """Return a tuple (model, scaler)."""
    model_path = model_path or DEFAULT_MODEL_PATH
    scaler_path = scaler_path or DEFAULT_SCALER_PATH
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"model not found at {model_path}")
    model = load_model(model_path)
    scaler = joblib.load(scaler_path)
    return model, scaler


def prepare_features(df, scaler):
    """Scale a dataframe of features and return an array suitable for prediction.
    Assumes one-step sequences (seq_len=1).
    """
    if "label" in df.columns:
        X_df = df.drop(columns=["label"])
    else:
        X_df = df.copy()
    X_df = X_df.select_dtypes(include=[np.number])
    features = X_df.values
    scaled = scaler.transform(features)
    return scaled.reshape((scaled.shape[0], 1, scaled.shape[1]))


def load_threshold(default=0.5, thr_file=None):
    thr_file = thr_file or os.path.join(ROOT, "models", "threshold.txt")
    if os.path.exists(thr_file):
        try:
            return float(open(thr_file).read().strip())
        except Exception:
            pass
    return default


def predict_dataframe(df, model, scaler, threshold=None, mode=None):
    """Return (probs, preds, threshold_used) for the given dataframe."""
    X = prepare_features(df, scaler)
    probs = model.predict(X)
    if mode:
        # preset modes -- could be loaded from file in future
        mode_map = {"balanced": threshold, "high": 0.11, "low": 0.7}
        threshold = mode_map.get(mode, threshold)
    if threshold is None:
        threshold = load_threshold()
    preds = (probs > threshold).astype(int).flatten()
    return probs, preds, threshold


def main():
    parser = argparse.ArgumentParser(description="Batch prediction using trained LSTM")
    parser.add_argument("--input", "-i", default=DEFAULT_DATA_PATH,
                        help="CSV file containing feature vectors to score")
    parser.add_argument("--output", "-o", help="optional path to write predictions (csv)")
    parser.add_argument("--model", help="path to trained LSTM model file")
    parser.add_argument("--scaler", help="path to scaler pickle")
    parser.add_argument("--threshold", type=float, default=None,
                        help="decision threshold for ransomware class")
    parser.add_argument("--mode", choices=["balanced","high","low"],
                        help="predefined mode: balanced=default, high=high-recall, low=high-precision")
    args = parser.parse_args()

    print(f"[+] loading data from {args.input}")
    df = pd.read_csv(args.input)
    model, scaler = load_detector(args.model, args.scaler)
    base_thr = args.threshold
    probs, preds, thr_used = predict_dataframe(df, model, scaler,
                                               threshold=base_thr,
                                               mode=args.mode)
    print(f"using threshold = {thr_used}")
    print("[+] Prediction Summary:")
    print("Total samples:", len(preds))
    print("Benign:", int((preds == 0).sum()))
    print("Ransomware:", int((preds == 1).sum()))

    if args.output:
        out_df = df.copy()
        out_df["prob_ransomware"] = probs.flatten()
        out_df["predicted_label"] = preds
        out_df.to_csv(args.output, index=False)
        print(f"wrote results to {args.output}")


if __name__ == "__main__":
    main()
