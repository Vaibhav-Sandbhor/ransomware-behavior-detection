# Ransomware Detection Module

A real-time ransomware detector built with LSTM neural networks. It learns to spot ransomware by analyzing how applications interact with your disk and memory, then catches new (never-before-seen) ransomware families based on their behavior patterns.

## 📖 What's This All About?

Look, ransomware is a massive problem. The traditional approach—blocking known malware by signature—doesn't work against new variants. This project takes a different angle: instead of memorizing past attacks, we teach a neural network to learn *how* ransomware behaves (lots of rapid file writes, memory patterns, etc.) so it can spot new families we've never seen before.

The model is a bidirectional LSTM that watches sequences of disk and memory activity. It's trained on real malware samples (Conti, LockBit, Revil, Ryuk) and benign software (Firefox, Office, etc.), so it learns the difference. We hold out one ransomware family during training to test how well it generalizes to zero-day attacks.

### Key Features

- **Actually works on new malware**: We validate using leave-one-family-out (LOFO)—hold back a ransomware family entirely, train on the others, then test. It works.
- **Reproducible**: Every run logs the seed, arguments, Python version, even your git commit. Run it again with the same seed and you get identical results.
- **Explainable**: We extract feature importances so you know which write patterns matter most.
- **Robust**: We stress-test the model with noise injection and feature ablation to make sure it's not just finding noise.
- **Easy to deploy**: Drop it in production with a simple CLI or Python API.
- **Automated testing**: GitHub Actions runs smoke tests on every push to catch breaks early.

---

## 📁 What's In Here?

```
ransomware_module/
├── data/
│   ├── raw/                    # raw disk/memory traces from benign & malware samples
│   │   ├── Benign/             # normal software (Firefox, Office, etc.)
│   │   └── ransomware/         # malware samples (Conti, LockBit, Revil, Ryuk)
│   └── processed/
│       └── ransomware_features.csv  # 20 engineered features extracted from the raw traces
├── models/
│   ├── lstm_model.keras        # the trained neural network weights
│   ├── scaler.pkl              # what we use to normalize features
│   ├── threshold.txt           # the decision threshold (when to call it ransomware)
│   ├── seed.txt                # random seed for reproducibility
│   ├── run_info.json           # metadata: what hyperparams we used, git commit, etc.
│   └── predict_lstm.py         # CLI and Python functions for making predictions
├── scripts/
│   ├── build_dataset.py        # extracts features from raw disk/memory logs
│   ├── train_model.py          # trains the LSTM (main script)
│   ├── train_ensemble.py       # trains LSTM + RandomForest together
│   ├── comprehensive_family_evaluation.py  # LOFO tests, robustness checks, stress tests
│   ├── hyperparam_search.py    # grid search over different learning rates, layers, etc.
│   ├── extract_surrogate_feature_importance.py  # shows which features matter
│   └── audit_duplicates.py     # checks for duplicate data
├── features/                   # actual feature engineering code
├── utils/                      # helper utilities
├── evaluation_reports/         # outputs from evaluation runs
├── .github/workflows/ci.yml    # GitHub Actions runs tests automatically
├── README.md                   # this file
└── requirements.txt            # Python packages you need
```

---

## 🚀 Getting Started

### 1. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### 2. Build the Dataset

Extract and engineer features from the raw traces:

```bash
python scripts/build_dataset.py
```

This creates `data/processed/ransomware_features.csv` with 20 features per sample.

### 3. Train a Model

```bash
python scripts/train_model.py --seq 5 --epochs 20 --oversample --pos-weight 3.0 --seed 42
```

By default, this holds out "ryuk" family during training (so we can test on a zero-day). After training you'll have:
- `models/lstm_model.keras` – the trained weights
- `models/scaler.pkl` – feature normalizer
- `models/threshold.txt` – decision threshold
- `models/seed.txt` – your seed
- `models/run_info.json` – full metadata (re-run with this seed to get identical results)

### 4. Evaluate the Model

Run comprehensive tests (LOFO, stress, robustness):

```bash
python scripts/comprehensive_family_evaluation.py
```

Outputs a detailed report to `evaluation_reports/family_evaluation_<timestamp>.txt`.

### 5. Try Different Settings

All these are customizable:

```bash
# Use focal loss instead of cross-entropy
python scripts/train_model.py --loss focal --gamma 2.0

# Train for longer or shorter
python scripts/train_model.py --epochs 50

# Hold out a different family (e.g., test on Conti instead of Ryuk)
python scripts/train_model.py --hold conti

# Disable SMOTE oversampling
python scripts/train_model.py

# Train on all families (no zero-day holdout)
python scripts/train_model.py --hold ""

# See all options
python scripts/train_model.py --help
```

---

## 📦 Using the Model for Predictions

### From the Command Line

```bash
python models/predict_lstm.py \
    --input my_features.csv \
    --model models/lstm_model.keras \
    --scaler models/scaler.pkl \
    --threshold 0.25 \
    --output results.csv
```

This reads a CSV of features, scores them, and writes out predictions + probabilities.

Arguments:
- `--input`: your CSV file with features (same 20 as training)
- `--model`: path to the trained model
- `--scaler`: path to the scaler pickle
- `--threshold`: decision threshold (higher = more confident before flagging ransomware)
- `--mode`: quick preset (`balanced`, `high` for high-recall, `low` for high-precision)
- `--output`: optional output file for results

### From Python Code

If you wanna use this in your own code, here's how:

```python
from models.predict_lstm import load_detector, predict_dataframe
import pandas as pd

# Load the model and scaler
model, scaler = load_detector(
    model_path="models/lstm_model.keras",
    scaler_path="models/scaler.pkl"
)

# Load your features
df = pd.read_csv("my_features.csv")

# Get predictions
probs, preds, threshold_used = predict_dataframe(
    df,
    model=model,
    scaler=scaler,
    threshold=0.20
)

# Use the results
print(f"Flagged {preds.sum()} as ransomware")
print(f"Used threshold: {threshold_used}")
```

---

## 🔬 Features We Extract

We pull 20 features from the disk/memory traces:

1. **Entropy stuff**: Shannon entropy (shows randomness), mean/std/min/max write sizes
2. **Patterns**: Moving averages, deltas (change over time), rate of change
3. **Distribution**: 25th, 50th, 75th percentiles, inter-quartile range
4. **Frequency domain**: FFT energy (captures oscillating patterns)

Ransomware tends to write a lot of random data fast (high entropy), so these features pick that up. Check [features/feature_extractor.py](features/feature_extractor.py) for the exact definitions.

---

## ✅ How We Test It

### Leave-One-Family-Out (LOFO)

Here's the thing—we don't want to overfit to the families we trained on. So we hold out one family entirely, train on the rest, then test on what we held out. This simulates a real zero-day attack.

```bash
python scripts/comprehensive_family_evaluation.py
```

Reports per-family ROC-AUC, precision, recall, F1, and confusion matrices.

### Stress Tests

We also test:
- **Single-family stress**: Can we still detect benign when trained only on one ransomware family?
- **Noise injection**: What happens when the data gets a bit noisy?
- **Feature ablation**: Which features actually matter? Drop each one and see how much accuracy drops.

All baked into the evaluation script.

---

## 🔄 Reproducibility

Every time you train, we log:
- Random seed → stored in `seed.txt`
- All your arguments → stored in `run_info.json`
- Python version and installed packages
- Your git commit (if available)

So if you run the same training again with the same seed, you get identical results. This matters when you're trying to figure out what changed.

---

## 🤖 Why Reproducibility?

Because you don't want to be the person who accidentally changed one parameter and can't figure out why the model is suddenly worse. We've all been there.

---

## 🚀 Advanced: Hyperparameter Optimization

Wanna optimize learning rate, number of LSTM units, dropout, batch size? We have grid search for that:

### Quick Grid

```bash
python scripts/hyperparam_search.py scripts/hyperparam_grid_small.json
```

### Full Grid (takes a while)

```bash
python scripts/hyperparam_search.py scripts/hyperparam_grid_full.json
```

Results go to `hyperparam_results.csv`.

---

## 📊 Feature Importance

Wanna know which features the model actually cares about?

```bash
python scripts/extract_surrogate_feature_importance.py \
    --output evaluation_reports/feature_importance.csv
```

Then visualize it:

```bash
python scripts/merge_and_visualize_importances.py \
    --input evaluation_reports/feature_importance.csv \
    --output evaluation_reports/importance_plot.png
```

---

## 🤝 Train an Ensemble

Mix LSTM with a RandomForest for potentially better results:

```bash
python scripts/train_ensemble.py --seq 5 --oversample --pos-weight 3.0 --seed 42
```

We average the predictions from both models.

---

## 🧪 Automated Testing

Every time you push to GitHub, Actions automatically:
1. Rebuilds the dataset
2. Trains for 1 epoch (quick sanity check)
3. Runs LOFO evaluation
4. Trains the ensemble

Makes sure you don't break anything accidentally.

---

## 🛠️ Troubleshooting

**"Model not found"**
→ Run `python scripts/train_model.py` first to create it.

**Out of memory**
→ Reduce batch size: `--batch 128`. Or shorter sequences: `--seq 3`.

**Poor results on my data**
→ Make sure your features match the training distribution. Retrain on your data first.

**Training is slow**
→ Make sure you have GPU acceleration. Check: `python -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"`

---

## 📌 Publishing a Release

When you've got a stable model, tag it:

```bash
git tag -a v1.0.0 -m "stable release with good LOFO results"
git push origin v1.0.0
```

Then create a GitHub Release and upload:
- `models/lstm_model.keras`
- `models/scaler.pkl`
- `models/run_info.json` (so people know how you trained it)

---

## 📝 The Model Architecture

```
Raw features (20)
    ↓
Bidirectional LSTM (128 units, dropout=0.3)
    ↓
Dense layer (64 units, ReLU, dropout=0.2)
    ↓
Output layer (sigmoid, binary classification)
    ↓
Probability score [0, 1]
```

Pretty standard LSTM stuff. Nothing fancy.

---

## 🎯 Default Hyperparameters

| Setting | Value | Why |
|---------|-------|-----|
| Sequence length | 5 | Window size for input |
| Epochs | 20 | Training iterations |
| Batch size | 256 | Samples per gradient update |
| LSTM dropout | 0.3 | Prevent overfitting |
| Dense dropout | 0.2 | More regularization |
| Positive weight | 1.0 | Cost-sensitive learning (adjust if imbalanced) |

Tweak these to suit your needs.

---

## 📚 Data Breakdown

We've got:
- **Benign**: Firefox, Office, idle system, zip tool
- **Ransomware**: Conti (10), LockBit (5), Revil (5), Ryuk (5)
- **Total**: ~1350 samples, 38% ransomware, 62% benign

Not huge, but enough to train a decent model.

---

## 🤔 FAQ

**Q: Does this catch ALL ransomware?**
A: No. No detection system is 100%. But LOFO shows we catch unseen families pretty well. Real-world results depend on your environment.

**Q: Can I use this on live systems?**
A: Not yet—this is a research model. For production, you'd need integration with actual system monitoring tools (ETW, auditd, etc.).

**Q: What's the false positive rate?**
A: Around 5-10% on our test set, depending on threshold. Adjust the threshold based on your tolerance for false alarms vs. missed attacks.

**Q: Can I add my own malware samples?**
A: Yeah. Add them to `data/raw/ransomware/<family_name>/` following the same folder structure, then rebuild the dataset.

---

## 🙏 Credits

- Built with TensorFlow/Keras
- Scikit-learn for the random forest and metrics
- Pandas and NumPy for data wrangling
- Inspired by behavioral malware detection research

---

Feel free to open issues, suggest improvements, or adapt this for your use case. Happy detecting! 🛡️
