# Ransomware Detection Module

This repository implements a real-time ransomware detection system based on a
bi-directional LSTM model trained on disk and memory activity features.  It
includes tools for dataset construction, model training, evaluation, explainable
importances, hyperparameter exploration, and deployment.

---

## 📁 Repository Structure

```
./data/processed     # engineered features and pre-built datasets
./models             # trained model files, scalers, thresholds, logs
./scripts            # main utilities (training, evaluation, search, etc.)
./utils              # helper modules (sequence building, feature pipeline)
./features           # feature extractor code
./ransomware_module  # packaged subset for distribution/analysis
README.md            # this file
requirements.txt     # Python dependencies
.github/workflows/ci.yml  # CI smoke tests
```

---

## 🚀 Quickstart

Install dependencies and prepare the dataset:

```bash
python -m pip install -r requirements.txt
python scripts/build_dataset.py   # regenerates `data/processed/ransomware_features.csv`
```

Train a detector (holds out `ryuk` as a zero-day by default):

```bash
python scripts/train_model.py --seq 5 --epochs 20 --oversample --pos-weight 3.0
```

You can override any hyperparameters, family to hold out, loss type (including
`--loss focal`), etc.  See `--help` for details.

Run a comprehensive evaluation (LOFO, stress tests, robustness) and review
`evaluation_reports/family_evaluation_<timestamp>.txt`:

```bash
python scripts/comprehensive_family_evaluation.py
```

Train an ensemble (LSTM + RandomForest) with the same options:

```bash
python scripts/train_ensemble.py --seq 5 --oversample --pos-weight 3.0
```

---

## 📦 Deployment & Prediction

A lightweight CLI wrapper is provided in `models/predict_lstm.py`.  It can be
used directly or imported as a module.

```bash
python models/predict_lstm.py --input path/to/features.csv \
    --model models/lstm_model.keras --scaler models/scaler.pkl \
    --threshold 0.2 --output results.csv
```

The script handles threshold modes (`balanced`, `high`, `low`) and writes
probabilities/predictions when `--output` is specified.  The functions
`load_detector()` and `predict_dataframe()` can be used in other Python code for
integration into services or pipelines.

---

## ⚙️ Reproducibility

All training utilities accept a `--seed` argument; seeds are logged to
`models/seed.txt`.  A `run_info.json` file (or `ensemble_run_info.json`) is
created containing:

* timestamp and CLI arguments
* Python version and installed packages
* Git commit hash (if repository present)

These records, along with the fixed seeds and deterministic TensorFlow settings,
enable exact reruns of experiments.

---

## 🧪 Continuous Integration

The GitHub Actions workflow (`.github/workflows/ci.yml`) performs a minimal
smoke test on every push or pull request.  It rebuilds the dataset, runs a
single training epoch, performs a LOFO evaluation, and trains an ensemble, all
using the default settings.  The job ensures that core scripts remain functional
and that outputs are produced without errors.

---

## 📌 Publishing a Release

When you're satisfied with a commit and results, tag it in git and push the
tag:

```bash
git tag -a v1.0.0 -m "first stable release"
git push origin v1.0.0
```

You can then create a GitHub release from the tag and upload trained model
artifacts (e.g. `lstm_model.keras`, `scaler.pkl`, thresholds).  The information
in `run_info.json` should accompany any published model so others can reproduce
its training conditions.

---

## 📝 Additional Notes

* Hyperparameter grids live under `scripts/` (`hyperparam_grid_small.json`/
  `hyperparam_grid_full.json`).  A helper script (`hyperparam_search.py`) can
  iterate them and record results.
* Duplicate data detection is provided by `scripts/audit_duplicates.py`.
* Surrogate feature importance extraction and visualization are handled by
  `extract_surrogate_feature_importance.py` and
  `merge_and_visualize_importances.py`.

Feel free to extend the training, add new features, or adapt the deployment
code for your environment.  🛡️
