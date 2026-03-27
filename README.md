# 🛡️ CyberSIEM - AI-Powered Security Intelligence Platform

**CyberSIEM** is a comprehensive, AI-driven Security Information and Event Management (SIEM) platform that combines multiple threat detection modules with explainable machine learning, real-time monitoring, and an intuitive dashboard.

## 📋 Table of Contents

- [Overview](#-overview)
- [System Architecture](#-system-architecture)
- [Core Modules](#-core-modules)
  - [Ransomware Detection](#1-ransomware-detection-module)
  - [AI Port Scanner](#2-ai-port-scanner-risk-intelligence)
  - [Honeypot Monitor](#3-filesystem-honeypot-monitor)
  - [Dark Web Intelligence](#4-dark-web-intelligence-monitoring)
- [Getting Started](#-getting-started)
- [API Documentation](#-api-documentation)
- [Frontend Dashboard](#-frontend-dashboard)
- [Advanced Usage](#-advanced-usage)
- [Troubleshooting](#-troubleshooting)
- [Development](#-development)

---

## 🎯 Overview

CyberSIEM integrates four core security modules into a unified platform:

1. **Ransomware Detection** - LSTM-based behavioral analysis for zero-day ransomware detection
2. **AI Port Scanner** - ML-powered Nmap analysis with XGBoost risk scoring and SHAP explainability  
3. **Honeypot Monitor** - Real-time filesystem decoy monitoring for early threat detection
4. **Dark Web Intelligence** - Threat intelligence gathering from dark web sources (development)

### Why CyberSIEM?

- ✅ **Zero-day detection** - Detects unknown ransomware families using behavioral patterns
- ✅ **Explainable AI** - SHAP values and feature importance for all ML predictions
- ✅ **Production-ready** - FastAPI backend, React frontend, containerizable architecture
- ✅ **Reproducible** - All experiments logged with seeds, parameters, and metadata
- ✅ **Comprehensive testing** - Leave-one-family-out validation, stress tests, Monte Carlo simulations
- ✅ **Real-time monitoring** - Live honeypot events and ransomware detection pipeline

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (React + Vite)                   │
│              http://localhost:5173                           │
│  ┌──────────┬──────────┬──────────┬──────────┐             │
│  │Dashboard │Ransomware│Port Scan │ Honeypot │             │
│  │Overview  │ Details  │ Analysis │   Logs   │             │
│  └──────────┴──────────┴──────────┴──────────┘             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ├─── REST API ───┐
                          │                  │
┌─────────────────────────▼─────┐  ┌───────▼──────────────┐
│   Main API (port 8000)         │  │ AI Port Scanner API  │
│   /api/ransomware/*            │  │    (port 8001)       │
│   /api/honeypot/*              │  │  /scan/target        │
│   /api/portscan/scan           │  │  /scan (XML upload)  │
│   /scan (malware detection)    │  │  /report/{scan_id}   │
└────────────────────────────────┘  └──────────────────────┘
         │                                   │
         ├─── ML Models ────                 ├─── XGBoost + SHAP ───
         │                                   │
    ┌────▼─────┐  ┌──────────┐         ┌────▼────────┐
    │  LSTM    │  │ Honeypot │         │ Port Risk   │
    │ Detector │  │Simulator │         │  Database   │
    └──────────┘  └──────────┘         └─────────────┘
```

**Component Communication:**
- Frontend (`localhost:5173`) → Main API (`localhost:8000`) for ransomware & honeypot
- Frontend (`localhost:5173`) → Port Scanner API (`localhost:8001`) for network scans
- All APIs use CORS to allow cross-origin requests

---

## 🔧 Core Modules

### 1. Ransomware Detection Module

A real-time ransomware detector built with LSTM neural networks that learns ransomware behavior patterns rather than relying on signatures.

#### Features

- **Bidirectional LSTM** - 128 units with dropout regularization
- **20 behavioral features** - Entropy, write patterns, frequency analysis
- **Leave-One-Family-Out (LOFO) validation** - Tests on unseen ransomware families
- **Integrated honeypot pipeline** - End-to-end detection from honeypot → features → ML → alerts

#### Quick Start

```bash
# 1. Build dataset from raw traces
python ransomware_module/scripts/build_dataset.py

# 2. Train LSTM model (holds out Ryuk for zero-day testing)
python ransomware_module/scripts/train_model.py --seq 5 --epochs 20 --oversample --seed 42

# 3. Run comprehensive evaluation
python ransomware_module/scripts/comprehensive_family_evaluation.py

# 4. Make predictions on new data
python ransomware_module/models/predict_lstm.py --input data.csv --threshold 0.25
```

#### API Endpoints

```bash
POST /api/ransomware/run-pipeline      # Run honeypot → features → predict
GET  /api/ransomware/predictions       # Get detection results
GET  /api/ransomware/alerts            # Get critical alerts  
GET  /api/honeypot/log                 # Get honeypot events
```

#### Model Architecture

```
Input: 20 features × 5 timesteps
  ↓
Bidirectional LSTM (128 units, dropout=0.3)
  ↓
Dense (64 units, ReLU, dropout=0.2)
  ↓
Output: Sigmoid probability [0, 1]
```

#### Training Families

- **Ransomware**: Conti (10), LockBit (5), Revil (5), Ryuk (5)
- **Benign**: Firefox, Office, idle system, compression tools
- **Total**: ~1350 samples (38% ransomware, 62% benign)

---

### 2. AI Port Scanner Risk Intelligence

ML-powered network scanner that transforms Nmap results into actionable security intelligence using XGBoost classification and SHAP explainability.

#### Features

- **XGBoost Risk Scoring** - Trained on 1200+ synthetic scans with CVE data
- **SHAP Explainability** - Shows which ports/services drive risk scores
- **Hybrid Scoring** - Combines ML predictions with port intelligence database
- **Real-time Scanning** - Direct IP/hostname scanning via Nmap integration
- **Multi-tier Risk Classification** - Low, Medium, High, Critical

#### Quick Start

```bash
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer

# Start the API server (must run on port 8001 for frontend)
python api.py

# Or with uvicorn
uvicorn api:app --host 0.0.0.0 --port 8001 --reload
```

#### API Endpoints

```bash
POST /scan/target          # Scan IP/hostname (body: {"target": "192.168.1.1"})
POST /scan                 # Upload Nmap XML file
GET  /report/{scan_id}     # Get detailed report with SHAP analysis
GET  /health               # Health check
```

#### Example: Scan a Target

```bash
curl -X POST http://localhost:8001/scan/target \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'
```

Returns:
```json
{
  "scan_id": "a3f9c2b1",
  "dashboard": [{
    "host": "127.0.0.1",
    "final_risk": "Medium",
    "risk_score": 0.68,
    "security_score": 72,
    "open_ports": [22, 80, 443, 3306],
    "recommendations": [
      "Close or restrict port 3306 (mysql)",
      "Enable firewall for high-risk services"
    ]
  }],
  "report": [/* detailed technical analysis with SHAP */]
}
```

#### Port Risk Database

- **HIGH**: SSH (22), Telnet (23), SMB (445), RDP (3389), MySQL (3306)
- **MEDIUM**: HTTP (80), HTTPS (443), SMTP (587)  
- **LOW**: Other common services

---

### 3. Filesystem Honeypot Monitor

Lightweight honeypot system that creates decoy files and monitors for unauthorized access patterns.

#### Features

- **Decoy Generation** - High-entropy bait files that mimic valuable data
- **Real-time Monitoring** - Watchdog-based file system event tracking
- **Behavioral Scoring** - Suspicious activity detection via entropy + write patterns
- **JSONL Logging** - Structured logs for analysis and ML integration
- **Cross-platform** - Works on Windows, Linux, macOS

#### Quick Start

```bash
# Run standalone honeypot
python ransomware_module/honeypot/honeypot_manager.py --path /target/dir --decoys 10

# Or use the integrated pipeline (via API)
curl -X POST http://localhost:8000/api/ransomware/run-pipeline
```

#### Honeypot Scoring Logic

```
score = (
    write_count × 0.3 +
    rename_count × 0.25 +
    extension_changes × 0.25 +
    entropy_delta × 0.2
)

if score >= 0.7:  CRITICAL (ransomware likely)
elif score >= 0.4:  WARNING (suspicious)
else:  INFO (normal activity)
```

#### Monte Carlo Validation

Test honeypot performance at scale:

```bash
python ransomware_module/tests/monte_carlo_validation.py --seed 42 --runs 500
```

Generates:
- False positive/true positive rates
- Detection latency distributions  
- Score/probability correlation plots

---

### 4. Dark Web Intelligence Monitoring

**Status:** Development/Placeholder

Monitors dark web sources for threat intelligence, credential leaks, and ransomware group activity.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9+
- Node.js 16+ (for frontend)
- Nmap installed and in PATH
- 4GB RAM minimum
- (Optional) CUDA GPU for faster training

### Installation

#### 1. Clone Repository

```bash
git clone <repository-url>
cd CyberSIEM
```

#### 2. Backend Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install AI Port Scanner dependencies
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer
pip install -r requirements_api.txt
cd ../..
```

#### 3. Frontend Setup

```bash
cd frontend
npm install
cd ..
```

#### 4. Download/Train Models

**Ransomware Model:**
```bash
# Option A: Train from scratch
python ransomware_module/scripts/train_model.py --seq 5 --epochs 20 --seed 42

# Option B: Download pretrained (if available)
# Place lstm_model.keras and scaler.pkl in ransomware_module/models/
```

**Port Scanner Model:**
```bash
# Models should be in AI_PortScan_Analyzer/AI_PortScan_Analyzer/model/
# If missing, follow the training guide in that module's README
```

### Running the Platform

#### Terminal 1: Main API Server

```bash
# From project root
source venv/bin/activate  # Windows: venv\Scripts\activate
uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload
```

#### Terminal 2: Port Scanner API

```bash
# From project root
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer
python api.py

# Or with uvicorn
uvicorn api:app --host 0.0.0.0 --port 8001 --reload
```

#### Terminal 3: Frontend

```bash
cd frontend
npm run dev
```

Access the dashboard at: **http://localhost:5173**

---

## 📡 API Documentation

### Main API (Port 8000)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scan` | POST | Analyze malware sample features |
| `/api/ransomware/run-pipeline` | POST | Run full ransomware detection pipeline |
| `/api/ransomware/predictions` | GET | Get ransomware predictions |
| `/api/ransomware/alerts` | GET | Get critical alerts |
| `/api/honeypot/log` | GET | Get honeypot events |
| `/api/portscan/scan` | POST | Quick localhost port scan |

### Port Scanner API (Port 8001)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/scan/target` | POST | Scan IP/hostname |
| `/scan` | POST | Upload Nmap XML |
| `/report/{scan_id}` | GET | Detailed report |
| `/scans` | GET | List all scans |
| `/docs` | GET | Interactive API docs |

**Important:** The frontend expects the Port Scanner API on port 8001. Do not change this without updating `frontend/src/servives/api.js`.

### Interactive API Documentation

- Main API: http://localhost:8000/docs
- Port Scanner API: http://localhost:8001/docs

---

## 🎨 Frontend Dashboard

The React-based dashboard provides:

- **Overview** - System health, active threats, statistics
- **Ransomware Details** - Detection results, confidence scores, timeline
- **Port Scan Analysis** - Network risk assessment, service breakdown
- **Honeypot Logs** - Real-time decoy file activity
- **Dark Web** - Threat intelligence feeds (development)

### Pages

- `/` - Dashboard overview
- `/ransomware` - Ransomware detection details  
- `/portscan` - AI port scanner interface
- `/honeypot` - Honeypot event logs
- `/darkweb` - Dark web monitoring

### Technologies

- React 18
- Vite (build tool)
- React Router (navigation)
- Custom CSS (dark theme)

---

## 🎓 Advanced Usage

### Ransomware Module

#### Leave-One-Family-Out Evaluation

```bash
python ransomware_module/scripts/comprehensive_family_evaluation.py
```

Output: `evaluation_reports/family_evaluation_<timestamp>.txt`

#### Hyperparameter Tuning

```bash
# Quick grid search
python ransomware_module/scripts/hyperparam_search.py scripts/hyperparam_grid_small.json

# Full grid (slow)
python ransomware_module/scripts/hyperparam_search.py scripts/hyperparam_grid_full.json
```

#### Feature Importance Analysis

```bash
python ransomware_module/scripts/extract_surrogate_feature_importance.py \
    --output evaluation_reports/feature_importance.csv

python ransomware_module/scripts/merge_and_visualize_importances.py \
    --input evaluation_reports/feature_importance.csv \
    --output evaluation_reports/importance_plot.png
```

#### Train Ensemble (LSTM + RandomForest)

```bash
python ransomware_module/scripts/train_ensemble.py --seq 5 --oversample --seed 42
```

#### Custom Training Options

```bash
# Use focal loss instead of binary cross-entropy
python ransomware_module/scripts/train_model.py --loss focal --gamma 2.0

# Train for longer
python ransomware_module/scripts/train_model.py --epochs 50

# Hold out a different family (test on Conti instead of Ryuk)
python ransomware_module/scripts/train_model.py --hold conti

# Disable SMOTE oversampling
python ransomware_module/scripts/train_model.py --no-oversample

# Train on all families (no zero-day holdout)
python ransomware_module/scripts/train_model.py --hold ""
```

### Port Scanner Module

#### CLI Usage (Direct Script)

```bash
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer
python scripts/predict_risk.py scan.xml
```

#### Batch Processing

```python
from scripts.predict_risk import analyze_scan

results = analyze_scan("nmap_output.xml")
for host in results["dashboard"]:
    print(f"{host['host']}: {host['final_risk']} (score: {host['risk_score']})")
```

---

## 🛠️ Troubleshooting

### Common Issues

#### 1. Port Scanner Returns 408 Timeout

**Symptoms:**
```
INFO: 127.0.0.1:43805 - "POST /scan/target HTTP/1.1" 408 Request Timeout
```

**Solutions:**
- Ensure Nmap is installed: `nmap --version`
- Check Windows firewall isn't blocking Nmap
- Target might be unreachable - try `127.0.0.1` first
- Scan timeout reduced to 60s - check network connectivity
- Try a simpler target with fewer ports

#### 2. "Cannot reach AI Port Scanner at http://127.0.0.1:8001"

**Solutions:**
```bash
# Check if server is running
curl http://localhost:8001/health

# Start server manually
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer
python api.py
```

#### 3. Ransomware Model "Model not found"

**Solution:**
```bash
# Train a new model
python ransomware_module/scripts/train_model.py --seq 5 --epochs 20 --seed 42
```

#### 4. Frontend Can't Connect to Backend

**Solutions:**
- Check both API servers are running (ports 8000 and 8001)
- Verify CORS settings in `api_server.py` and `api.py`
- Check browser console for CORS errors
- Ensure frontend expects correct ports in `frontend/src/servives/api.js`

#### 5. Out of Memory During Training

**Solution:**
```bash
# Reduce batch size and sequence length
python ransomware_module/scripts/train_model.py --seq 3 --batch 128
```

#### 6. XGBoost/sklearn Version Warnings

**Symptoms:**
```
InconsistentVersionWarning: Trying to unpickle estimator from version 1.6.1 when using version 1.8.0
```

**Solutions:**
```bash
# Option A: Retrain port scanner model with current scikit-learn version
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer
# (Follow training procedure in that module's documentation)

# Option B: Downgrade scikit-learn (not recommended)
pip install scikit-learn==1.6.1
```

#### 7. "Invalid HTTP request received" warnings

**Cause:** The port scanner is receiving malformed requests (possibly from actual port scans/attacks).

**Solution:** This is normal if your system is exposed to the network. The API properly rejects these requests.

### Checking GPU Acceleration

```bash
# TensorFlow (for ransomware LSTM)
python -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"

# XGBoost (for port scanner)
python -c "import xgboost; print(xgboost.get_config())"
```

---

## 👨‍💻 Development

### Project Structure

```
CyberSIEM/
├── ransomware_module/          # LSTM ransomware detection
│   ├── data/raw/               # Raw malware samples
│   ├── data/processed/         # Extracted features
│   ├── models/                 # Trained LSTM + metadata
│   ├── scripts/                # Training, evaluation, hyperparam search
│   ├── features/               # Feature extraction code
│   ├── honeypot/               # Decoy monitoring
│   │   ├── decoy_generator.py
│   │   ├── monitor.py
│   │   ├── scoring.py
│   │   └── honeypot_manager.py
│   ├── utils/                  # Honeypot feature extraction
│   └── tests/                  # Unit tests, Monte Carlo
├── AI_PortScan_Analyzer/       # XGBoost port scanner
│   └── AI_PortScan_Analyzer/
│       ├── api.py              # FastAPI server (port 8001)
│       ├── scripts/            # Risk analysis, prediction
│       │   └── predict_risk.py
│       ├── model/              # XGBoost model + SHAP
│       ├── data/               # Training datasets
│       └── nmap_scans/         # Sample scans
├── frontend/                   # React dashboard
│   ├── src/
│   │   ├── pages/              # Dashboard, Ransomware, PortScan, etc.
│   │   ├── servives/           # API clients
│   │   └── components/         # Reusable UI components
│   ├── dist/                   # Production build
│   └── package.json
├── features/                   # Feature extraction for malware
├── models/                     # Trained ransomware models
├── utils/                      # Shared utilities
├── api_server.py               # Main API (port 8000)
├── main.py                     # Legacy CLI entry point
└── requirements.txt            # Python dependencies
```

### Running Tests

**Ransomware Module:**
```bash
pytest ransomware_module/tests/
python ransomware_module/tests/monte_carlo_validation.py --seed 42
```

**Port Scanner:**
```bash
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer
pytest
```

### Adding New Ransomware Families

1. Add samples to `ransomware_module/data/raw/ransomware/<family_name>/`
2. Rebuild dataset:
   ```bash
   python ransomware_module/scripts/build_dataset.py
   ```
3. Retrain with new family as holdout:
   ```bash
   python ransomware_module/scripts/train_model.py --hold <family_name>
   ```

### Build Frontend for Production

```bash
cd frontend
npm run build
```

Serves static files from `frontend/dist/`.

---

## 📦 Model Files

### Ransomware Module (`ransomware_module/models/`)

- `lstm_model.keras` - Trained LSTM weights
- `scaler.pkl` - StandardScaler for feature normalization
- `threshold.txt` - Decision threshold (typically 0.20-0.30)
- `seed.txt` - Random seed for reproducibility
- `run_info.json` - Training metadata (hyperparams, git commit, timestamps)

### Port Scanner (`AI_PortScan_Analyzer/AI_PortScan_Analyzer/model/`)

- `model_*.pkl` - Calibrated XGBoost classifier
- `scaler_*.pkl` - Feature scaler
- Port risk database (embedded in `api.py`)

---

## 🔄 Reproducibility

All training runs are logged with:

- **Random seed** → `seed.txt`
- **All arguments** → `run_info.json`
- **Python version** and installed packages
- **Git commit hash** (if available)

Run the same training with the same seed to get identical results:

```bash
# First run
python ransomware_module/scripts/train_model.py --seed 42

# Later (reproducing results)
python ransomware_module/scripts/train_model.py --seed 42
```

---

## 🌟 Features Summary

| Feature | Ransomware Module | Port Scanner | Honeypot |
|---------|------------------|--------------|----------|
| ML Algorithm | Bidirectional LSTM | XGBoost + Calibration | Rule-based scoring |
| Explainability | Feature importance | SHAP values | Transparent scoring |
| Zero-day detection | ✅ LOFO validation | ✅ Generalizes to new networks | ✅ Behavioral patterns |
| Real-time | ✅ API endpoint | ✅ Direct scanning | ✅ Watchdog monitoring |
| Training data | 1350 samples | 1200+ scans | Simulated events |
| Accuracy | ~95% LOFO | ~92% test set | Tunable thresholds |

---

## 📚 References & Credits

### Technologies Used

- **TensorFlow/Keras** - LSTM neural networks
- **XGBoost** - Gradient boosting for port risk
- **SHAP** - Model explainability
- **FastAPI** - High-performance API framework
- **React + Vite** - Modern frontend stack
- **Scikit-learn** - ML utilities, calibration
- **Watchdog** - Filesystem monitoring
- **Nmap** - Network scanning

### Malware Families

- Conti, LockBit, Revil, Ryuk ransomware families
- CVE database for port vulnerabilities

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 📄 License

This project is for educational and research purposes.

---

## 🆘 Support

If you encounter issues:

1. Check the [Troubleshooting](#-troubleshooting) section
2. Review server logs for error messages
3. Verify all dependencies are installed
4. Check that ports 8000 and 8001 are not in use
5. Open an issue with detailed error logs

---

## 🎯 Roadmap

- [ ] Deploy containerized version (Docker/Kubernetes)
- [ ] Add user authentication and multi-tenancy
- [ ] Implement dark web scraping module
- [ ] Add email/Slack alerting
- [ ] Create mobile app dashboard
- [ ] Add network traffic analysis module
- [ ] Implement automated incident response workflows

---

**Built with ❤️ for cybersecurity research and education**
