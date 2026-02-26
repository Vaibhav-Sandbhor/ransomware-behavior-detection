"""
train_model.py
==============
Module 3: LSTM Model Training Pipeline

Trains a bidirectional LSTM classifier on behavioral feature sequences and
saves the model + fitted scaler for use by the inference engine.

Architecture
------------
  Input  : (batch, SEQ_LEN=5, N_FEATURES=10)
  Layer 1: Bidirectional LSTM  64 units, return_sequences=True
  Layer 2: Dropout  0.30
  Layer 3: Bidirectional LSTM  32 units
  Layer 4: Dropout  0.30
  Layer 5: Dense  16 units, ReLU
  Layer 6: Dense   1 unit,  Sigmoid  -> ransomware probability

Outputs
-------
  ransomware_module/models/lstm_model.keras   – trained model
  ransomware_module/models/scaler.pkl         – StandardScaler
  ransomware_module/models/threshold.txt      – optimised decision threshold
  ransomware_module/models/history.json       – training history

Usage:
    python -m ransomware_module.scripts.train_model
    python -m ransomware_module.scripts.train_model \\
        --data data/training_data.csv \\
        --epochs 30 --batch-size 32 --seed 42
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_MODULE_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR    = _MODULE_ROOT / "data"
_MODELS_DIR  = _MODULE_ROOT / "models"

DEFAULT_DATA    = _DATA_DIR   / "training_data.csv"
MODEL_OUT       = _MODELS_DIR / "lstm_model.keras"
SCALER_OUT      = _MODELS_DIR / "scaler.pkl"
THRESHOLD_OUT   = _MODELS_DIR / "threshold.txt"
HISTORY_OUT     = _MODELS_DIR / "history.json"

SEQ_LEN   = 5
N_FEATURES = 10   # must match BEHAVIORAL_FEATURES

from ransomware_module.utils.feature_extractor import BEHAVIORAL_FEATURES


# ---------------------------------------------------------------------------
# Data loading + preparation
# ---------------------------------------------------------------------------

def load_data(data_path: Path):
    import pandas as pd
    df = pd.read_csv(data_path)
    print(f"[TRAIN] Loaded {len(df)} rows from {data_path}")
    print(f"[TRAIN] Class balance: {df['label'].value_counts().to_dict()}")
    return df


def prepare_sequences(df, seq_len: int = SEQ_LEN):
    """
    Scale features and build overlapping sequences for LSTM training.

    Returns
    -------
    X_seq : ndarray (n_sequences, seq_len, N_FEATURES)
    y_seq : ndarray (n_sequences,)
    scaler: fitted StandardScaler
    """
    from sklearn.preprocessing import StandardScaler
    from sklearn.utils import shuffle as sk_shuffle

    feat_cols = [c for c in BEHAVIORAL_FEATURES if c in df.columns]
    X = df[feat_cols].fillna(0).values.astype(np.float32)
    y = df["label"].values.astype(np.float32)

    # Shuffle before sequencing to avoid temporal leakage across classes
    idx = np.random.permutation(len(X))
    X, y = X[idx], y[idx]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Build sliding window sequences
    n = len(X_scaled)
    X_seq_list = []
    y_seq_list = []
    for i in range(n - seq_len + 1):
        X_seq_list.append(X_scaled[i: i + seq_len])
        y_seq_list.append(y[i + seq_len - 1])

    X_seq = np.array(X_seq_list, dtype=np.float32)
    y_seq = np.array(y_seq_list, dtype=np.float32)
    print(f"[TRAIN] Sequences: {X_seq.shape}  Labels: {y_seq.shape}")
    return X_seq, y_seq, scaler


# ---------------------------------------------------------------------------
# Model architecture
# ---------------------------------------------------------------------------

def build_lstm_model(seq_len: int = SEQ_LEN, n_features: int = N_FEATURES):
    """Return compiled Keras LSTM model."""
    from tensorflow import keras
    from tensorflow.keras import layers

    inp = keras.Input(shape=(seq_len, n_features), name="behavioral_sequence")

    x = layers.Bidirectional(
        layers.LSTM(64, return_sequences=True, dropout=0.20, recurrent_dropout=0.10),
        name="bilstm_1",
    )(inp)
    x = layers.Dropout(0.30, name="dropout_1")(x)

    x = layers.Bidirectional(
        layers.LSTM(32, return_sequences=False, dropout=0.20),
        name="bilstm_2",
    )(x)
    x = layers.Dropout(0.30, name="dropout_2")(x)

    x = layers.Dense(16, activation="relu", name="fc_1")(x)
    out = layers.Dense(1, activation="sigmoid", name="output")(x)

    model = keras.Model(inputs=inp, outputs=out, name="ransomware_lstm")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.AUC(name="auc"),
                 keras.metrics.Recall(name="recall"),
                 keras.metrics.Precision(name="precision")],
    )
    model.summary()
    return model


# ---------------------------------------------------------------------------
# Optimal threshold search
# ---------------------------------------------------------------------------

def find_optimal_threshold(
    model,
    X_val: np.ndarray,
    y_val: np.ndarray,
    candidates: int = 100,
) -> float:
    """
    Grid-search over [0.05, 0.95] for the threshold that maximises F1 on the
    validation set.
    """
    probs = model.predict(X_val, verbose=0).flatten()
    best_thr, best_f1 = 0.5, 0.0
    for t in np.linspace(0.05, 0.95, candidates):
        preds = (probs >= t).astype(int)
        tp = int(((preds == 1) & (y_val == 1)).sum())
        fp = int(((preds == 1) & (y_val == 0)).sum())
        fn = int(((preds == 0) & (y_val == 1)).sum())
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        if f1 > best_f1:
            best_f1, best_thr = f1, float(t)
    print(f"[TRAIN] Optimal threshold: {best_thr:.4f}  (F1={best_f1:.4f})")
    return best_thr


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------

def evaluate_model(model, X_test: np.ndarray, y_test: np.ndarray, threshold: float) -> dict:
    probs = model.predict(X_test, verbose=0).flatten()
    preds = (probs >= threshold).astype(int)
    tp = int(((preds == 1) & (y_test == 1)).sum())
    tn = int(((preds == 0) & (y_test == 0)).sum())
    fp = int(((preds == 1) & (y_test == 0)).sum())
    fn = int(((preds == 0) & (y_test == 1)).sum())
    total = tp + tn + fp + fn
    accuracy  = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    metrics = {
        "accuracy":  round(accuracy,  4),
        "precision": round(precision, 4),
        "recall":    round(recall,    4),
        "f1":        round(f1,        4),
        "fpr":       round(fpr,       4),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
    }
    print("[TRAIN] ─── Test-set Metrics ─────────────────────")
    print(f"  Accuracy  : {metrics['accuracy']:.4f}")
    print(f"  Precision : {metrics['precision']:.4f}")
    print(f"  Recall    : {metrics['recall']:.4f}")
    print(f"  F1        : {metrics['f1']:.4f}")
    print(f"  FPR       : {metrics['fpr']:.4f}")
    print(f"  Confusion : TP={tp} TN={tn} FP={fp} FN={fn}")
    print("─────────────────────────────────────────────────")
    if metrics["accuracy"] < 0.95:
        print("[TRAIN] WARNING: accuracy below 0.95 target")
    if metrics["recall"] < 0.95:
        print("[TRAIN] WARNING: recall below 0.95 target")
    return metrics


# ---------------------------------------------------------------------------
# Main training pipeline
# ---------------------------------------------------------------------------

# ============================================================
# sklearn MLP fallback (auto-used when TF DLL unavailable)
# ============================================================

def _tf_available() -> bool:
    import subprocess
    try:
        subprocess.check_call([sys.executable, "-c", "import tensorflow"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        return True
    except Exception:
        return False


def _sk_find_threshold(probs, y):
    best_thr, best_f1 = 0.5, 0.0
    for t in __import__("numpy").linspace(0.05, 0.95, 100):
        p  = (probs >= t).astype(int)
        tp = int(((p == 1) & (y == 1)).sum())
        fp = int(((p == 1) & (y == 0)).sum())
        fn = int(((p == 0) & (y == 1)).sum())
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec  = tp / (tp + fn) if (tp + fn) else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        if f1 > best_f1:
            best_f1, best_thr = f1, float(t)
    print("[TRAIN] Optimal threshold:", round(best_thr,4), "F1:", round(best_f1,4))
    return best_thr


def _sk_evaluate(probs, y, thr):
    _np = __import__("numpy")
    p  = (probs >= thr).astype(int)
    tp = int(((p==1)&(y==1)).sum()); tn = int(((p==0)&(y==0)).sum())
    fp = int(((p==1)&(y==0)).sum()); fn = int(((p==0)&(y==1)).sum())
    tot = tp+tn+fp+fn
    acc  = (tp+tn)/tot if tot else 0.0
    prec = tp/(tp+fp)  if (tp+fp) else 0.0
    rec  = tp/(tp+fn)  if (tp+fn) else 0.0
    fpr  = fp/(fp+tn)  if (fp+tn) else 0.0
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0.0
    print("\n[TRAIN] MLP Test Metrics:")
    print("  Accuracy :", round(acc,4),  "[OK]" if acc>=0.95 else "[WARN target >0.95]")
    print("  Precision:", round(prec,4)); print("  Recall   :", round(rec,4), "[OK]" if rec>=0.95 else "[WARN]")
    print("  F1       :", round(f1,4));   print("  FPR      :", round(fpr,4))
    print("  TP=%d TN=%d FP=%d FN=%d" % (tp,tn,fp,fn))
    return {"accuracy":round(acc,4),"precision":round(prec,4),"recall":round(rec,4),
            "f1":round(f1,4),"fpr":round(fpr,4),"tp":tp,"tn":tn,"fp":fp,"fn":fn}


def train_sklearn(data_path=None, seed=42):
    import json as _json, numpy as _np
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    if data_path is None:
        data_path = DEFAULT_DATA
    _np.random.seed(seed)
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)
    df = load_data(data_path)
    feat_cols = [c for c in BEHAVIORAL_FEATURES if c in df.columns]
    X = df[feat_cols].fillna(0).values.astype(_np.float32)
    y = df["label"].values.astype(_np.float32)
    idx = _np.random.permutation(len(X))
    X, y = X[idx], y[idx]
    sc = StandardScaler()
    Xs = sc.fit_transform(X).astype(_np.float32)
    X_tr,X_te,y_tr,y_te = train_test_split(Xs,y,test_size=0.15,random_state=seed,stratify=y)
    X_tr,X_va,y_tr,y_va = train_test_split(X_tr,y_tr,test_size=0.15,random_state=seed,stratify=y_tr)
    print("[TRAIN] sklearn split: train=%d val=%d test=%d" % (len(X_tr),len(X_va),len(X_te)))
    print("[TRAIN] Training MLPClassifier (sklearn fallback -- TF unavailable)...")
    mlp = MLPClassifier(hidden_layer_sizes=(128,64,32),activation="relu",solver="adam",
        alpha=1e-4,learning_rate_init=1e-3,max_iter=300,early_stopping=True,
        validation_fraction=0.1,n_iter_no_change=15,random_state=seed,verbose=True)
    mlp.fit(X_tr, y_tr)
    vp  = mlp.predict_proba(X_va)[:,1].astype(_np.float32)
    tp2 = mlp.predict_proba(X_te)[:,1].astype(_np.float32)
    thr = _sk_find_threshold(vp,  y_va.astype(_np.float32))
    mtr = _sk_evaluate(tp2, y_te.astype(_np.float32), thr)
    mlp_path = _MODELS_DIR / "mlp_model.pkl"
    import joblib as _jl
    _jl.dump(mlp, str(mlp_path)); _jl.dump(sc, str(SCALER_OUT))
    THRESHOLD_OUT.write_text(str(thr))
    HISTORY_OUT.write_text(_json.dumps({"loss_curve":[float(v) for v in mlp.loss_curve_],
        "test_metrics":mtr,"backend":"sklearn_mlp","threshold":thr,"n_iter":mlp.n_iter_},indent=2))
    print("[TRAIN] Saved:", mlp_path, "|", SCALER_OUT, "| thr:", round(thr,4))
    print("[TRAIN] sklearn MLP training complete.")


def train(
    data_path:  Path  = DEFAULT_DATA,
    epochs:     int   = 25,
    batch_size: int   = 64,
    val_split:  float = 0.15,
    test_split: float = 0.15,
    seq_len:    int   = SEQ_LEN,
    seed:          int   = 42,
    force_sklearn: bool  = False,
) -> None:
    """
    Full training pipeline:
        1. Load data
        2. Scale + build sequences
        3. Train/val/test split
        4. Build + train model with early stopping
        5. Find optimal threshold
        6. Evaluate on held-out test set
        7. Save model, scaler, threshold, history
    """
    if force_sklearn or not _tf_available():
        reason = "forced" if force_sklearn else "TF DLL unavailable"
        print("[TRAIN] Using sklearn MLP (" + reason + ")")
        train_sklearn(data_path, seed=seed)
        return
    import tensorflow as tf

    tf.random.set_seed(seed)
    np.random.seed(seed)

    _MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # ── 1. Load ────────────────────────────────────────────────────────────
    df = load_data(data_path)

    # ── 2. Features + sequences ────────────────────────────────────────────
    X_seq, y_seq, scaler = prepare_sequences(df, seq_len=seq_len)

    # ── 3. Split (train | val | test) ─────────────────────────────────────
    n = len(X_seq)
    n_test = max(1, int(n * test_split))
    n_val  = max(1, int(n * val_split))
    n_train = n - n_test - n_val

    idx = np.random.permutation(n)
    train_idx = idx[:n_train]
    val_idx   = idx[n_train: n_train + n_val]
    test_idx  = idx[n_train + n_val:]

    X_train, y_train = X_seq[train_idx], y_seq[train_idx]
    X_val,   y_val   = X_seq[val_idx],   y_seq[val_idx]
    X_test,  y_test  = X_seq[test_idx],  y_seq[test_idx]

    print(f"[TRAIN] Split — train:{len(X_train)}  val:{len(X_val)}  test:{len(X_test)}")

    # ── 4. Build + train ───────────────────────────────────────────────────
    from tensorflow.keras.callbacks import (
        EarlyStopping, ReduceLROnPlateau, ModelCheckpoint,
    )

    model = build_lstm_model(seq_len=seq_len, n_features=X_seq.shape[2])

    callbacks = [
        EarlyStopping(
            monitor="val_auc", patience=6, mode="max",
            restore_best_weights=True, verbose=1,
        ),
        ReduceLROnPlateau(
            monitor="val_loss", factor=0.5, patience=3, min_lr=1e-6, verbose=1,
        ),
        ModelCheckpoint(
            filepath=str(MODEL_OUT),
            monitor="val_auc", mode="max",
            save_best_only=True, verbose=1,
        ),
    ]

    # Class weights for any remaining imbalance
    n_pos = int(y_train.sum())
    n_neg = len(y_train) - n_pos
    class_weight = {0: 1.0, 1: n_neg / max(n_pos, 1)}

    print(f"[TRAIN] Starting training  epochs={epochs}  batch={batch_size}")
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=1,
    )

    # ── 5. Optimal threshold ───────────────────────────────────────────────
    threshold = find_optimal_threshold(model, X_val, y_val)

    # ── 6. Evaluate ────────────────────────────────────────────────────────
    metrics = evaluate_model(model, X_test, y_test, threshold)

    # ── 7. Save artefacts ─────────────────────────────────────────────────
    # Model already saved by ModelCheckpoint; save again as .h5 for compat
    model.save(str(MODEL_OUT))
    h5_path = _MODELS_DIR / "lstm_model.h5"
    model.save(str(h5_path))

    joblib.dump(scaler, str(SCALER_OUT))
    THRESHOLD_OUT.write_text(str(threshold))

    hist_data = {k: [float(v) for v in vals] for k, vals in history.history.items()}
    hist_data["test_metrics"] = metrics
    hist_data["threshold"]    = threshold
    HISTORY_OUT.write_text(json.dumps(hist_data, indent=2))

    print(f"\n[TRAIN] Saved model   -> {MODEL_OUT}")
    print(f"[TRAIN] Saved model   -> {h5_path}")
    print(f"[TRAIN] Saved scaler  -> {SCALER_OUT}")
    print(f"[TRAIN] Saved threshold ({threshold:.4f}) -> {THRESHOLD_OUT}")
    print(f"[TRAIN] Saved history -> {HISTORY_OUT}")
    print("\n[TRAIN] Training complete.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Train LSTM Ransomware Detector")
    p.add_argument("--data",       type=Path, default=DEFAULT_DATA,
                   help="training CSV (default: data/training_data.csv)")
    p.add_argument("--epochs",     type=int, default=25)
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--val-split",  type=float, default=0.15)
    p.add_argument("--test-split", type=float, default=0.15)
    p.add_argument("--seq-len",    type=int, default=SEQ_LEN)
    p.add_argument("--seed",       type=int, default=42)
    p.add_argument("--force-sklearn", action="store_true",
                   help="use sklearn MLP instead of TF LSTM")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    # Auto-generate dataset if not present
    if not args.data.exists():
        print(f"[TRAIN] Dataset not found at {args.data} — generating now…")
        from ransomware_module.scripts.build_dataset import build_dataset
        build_dataset(output=args.data, seed=args.seed)

    train(
        data_path=args.data,
        epochs=args.epochs,
        batch_size=args.batch_size,
        val_split=args.val_split,
        test_split=args.test_split,
        seq_len=args.seq_len,
        seed=args.seed,
        force_sklearn=getattr(args, "force_sklearn", False),
    )


if __name__ == "__main__":
    main()
