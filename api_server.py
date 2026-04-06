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
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timedelta, timezone
import threading
import logging
import bcrypt
from jose import JWTError, jwt
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func

from ransomware_module.features.feature_extractor import extract_features

# ─────────────────────────────────────────────────────────────────────────────
# Database Integration for Metrics & Events
# ─────────────────────────────────────────────────────────────────────────────
try:
    from database.init_db import init_database
    from database.session_manager import start_session, get_current_session
    from database.event_logger import log_ransomware_threat, log_port_open, log_honeypot_interaction
    from database.metrics_manager import store_metrics
    ENABLE_DB = True
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"⚠️  Database module not available: {e}. Running without persistence.")
    ENABLE_DB = False

# Global session ID (will be set on startup)
CURRENT_SESSION_ID = None

# ─────────────────────────────────────────────────────────────────────────────
# Authentication Configuration
# ─────────────────────────────────────────────────────────────────────────────

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "cybersiem-secret-key-change-in-production-12345678")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Database Configuration
DATABASE_URL = "sqlite:///./cybersiem_auth.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ─────────────────────────────────────────────────────────────────────────────
# Database Models
# ─────────────────────────────────────────────────────────────────────────────

class User(Base):
    """User model for authentication."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<User(id={self.id}, email={self.email}, name={self.name})>"

# Create tables
Base.metadata.create_all(bind=engine)

# ─────────────────────────────────────────────────────────────────────────────
# Pydantic Schemas for Auth
# ─────────────────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    """User registration schema."""
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    """User login schema."""
    email: str
    password: str

class UserResponse(BaseModel):
    """User response schema."""
    id: int
    name: str
    email: str

    class Config:
        from_attributes = True

class LoginResponse(BaseModel):
    """Login response with token."""
    access_token: str
    token_type: str
    user: UserResponse

class RegisterResponse(BaseModel):
    """Registration response."""
    id: int
    name: str
    email: str
    message: str

# ─────────────────────────────────────────────────────────────────────────────
# Authentication Utilities
# ─────────────────────────────────────────────────────────────────────────────

class PasswordManager:
    """Manages password hashing and verification."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        truncated_password = password[:72].encode('utf-8')
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(truncated_password, salt)
        return hashed.decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against a hashed password."""
        truncated_password = plain_password[:72].encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(truncated_password, hashed_bytes)


class JWTTokenManager:
    """Manages JWT token creation and verification."""

    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()

        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> dict:
        """Verify a JWT token and return the payload."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            email: str = payload.get("sub")
            if email is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return payload
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )


async def get_current_user(request: Request):
    """Get current user from JWT token (dependency injection)."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = parts[1]
    return JWTTokenManager.verify_token(token)


def get_db():
    """Database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_RANSOM_ROOT     = Path(__file__).parent / "ransomware_module"
_PREDICTIONS_LOG = _RANSOM_ROOT / "output" / "predictions_log.csv"
_ALERTS_LOG      = _RANSOM_ROOT / "output" / "alerts.log"
_HONEYPOT_LOG    = _RANSOM_ROOT / "honeypot" / "honeypot_log.csv"

app = FastAPI()

# CORS - must be after app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Initialize Database on Startup
# ─────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    """Initialize database and start a session on server startup."""
    global CURRENT_SESSION_ID, logger

    if ENABLE_DB:
        try:
            init_database()
            CURRENT_SESSION_ID = start_session()
            logger.info(f"✅ Database initialized with session ID: {CURRENT_SESSION_ID}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize database: {e}")
    else:
        logger.warning("⚠️  Database is disabled, running without persistence")

MODEL_PATH = os.path.join("ransomware_module", "models", "rf_model.joblib")
model = joblib.load(MODEL_PATH)

WINDOW_SIZE = 25

# ─────────────────────────────────────────────────────────────────────────────
# Dual Scan Mode: Simulation vs Real System Monitoring
# ─────────────────────────────────────────────────────────────────────────────

# Global scan state management for RANSOMWARE
_current_scan_mode = None  # "simulation" | "system" | None
_current_scan_thread = None
_scan_active = False
_scan_start_time = None
_scan_stop_requested = False

# Global scan state management for HONEYPOT
_honeypot_scan_mode = None  # "simulation" | "monitor" | None
_honeypot_scan_thread = None
_honeypot_scan_active = False
_honeypot_scan_start_time = None
_honeypot_scan_stop_requested = False

# Thread synchronization (shared for both ransomware and honeypot)
_scan_lock = threading.Lock()
_scan_event = threading.Event()

# Logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ─────────────────────────────────────────────────────────────────────────────
# Authentication Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post(
    "/auth/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user."""
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Create new user
    hashed_password = PasswordManager.hash_password(user_data.password)
    user = User(
        name=user_data.name,
        email=user_data.email,
        password=hashed_password,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return RegisterResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        message="User registered successfully",
    )


@app.post(
    "/auth/login",
    response_model=LoginResponse,
    tags=["Authentication"],
)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """Login user and return JWT token."""
    # Find user by email
    user = db.query(User).filter(User.email == credentials.email).first()
    if not user or not PasswordManager.verify_password(
        credentials.password, user.password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Create JWT token
    access_token = JWTTokenManager.create_access_token(data={"sub": user.email})

    return LoginResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.from_orm(user),
    )


@app.get("/auth/me", response_model=UserResponse, tags=["Authentication"])
def get_me(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current authenticated user."""
    user = db.query(User).filter(User.email == current_user.get("sub")).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return UserResponse.from_orm(user)


# ─────────────────────────────────────────────────────────────────────────────
# Data Retrieval APIs (Database Integration)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/metrics", tags=["Metrics"])
def get_metrics(current_user: dict = Depends(get_current_user)):
    """Get metrics timeline data for charts."""
    if not ENABLE_DB or CURRENT_SESSION_ID is None:
        return {"error": "Database not available"}

    try:
        from database.metrics_manager import get_metrics_for_session
        metrics = get_metrics_for_session(CURRENT_SESSION_ID)
        return {"metrics": metrics, "session_id": CURRENT_SESSION_ID}
    except Exception as e:
        logger.error(f"❌ Error fetching metrics: {e}")
        return {"error": str(e)}


@app.get("/api/events", tags=["Events"])
def get_events(current_user: dict = Depends(get_current_user)):
    """Get all threat events from current session."""
    if not ENABLE_DB or CURRENT_SESSION_ID is None:
        return {"error": "Database not available"}

    try:
        from database.db_manager import execute_query
        results = execute_query(
            """SELECT module, event_type, severity, details, timestamp
               FROM threat_events
               WHERE session_id = ?
               ORDER BY timestamp DESC
               LIMIT 100""",
            (CURRENT_SESSION_ID,)
        )
        events = [dict(row) for row in results]
        return {"events": events, "total": len(events)}
    except Exception as e:
        logger.error(f"❌ Error fetching events: {e}")
        return {"error": str(e)}


@app.get("/api/events/by-date", tags=["Events"])
def get_events_by_date(date: str, current_user: dict = Depends(get_current_user)):
    """
    Get threat events for a specific date.

    Query param: date (format: YYYY-MM-DD)
    """
    if not ENABLE_DB or CURRENT_SESSION_ID is None:
        return {"error": "Database not available"}

    try:
        from database.db_manager import execute_query
        results = execute_query(
            """SELECT module, event_type, severity, details, timestamp
               FROM threat_events
               WHERE session_id = ? AND DATE(timestamp) = ?
               ORDER BY timestamp DESC""",
            (CURRENT_SESSION_ID, date)
        )
        events = [dict(row) for row in results]
        return {"date": date, "events": events, "total": len(events)}
    except Exception as e:
        logger.error(f"❌ Error fetching events by date: {e}")
        return {"error": str(e)}


@app.get("/api/metrics/summary", tags=["Metrics"])
def get_metrics_summary(current_user: dict = Depends(get_current_user)):
    """Get summary statistics for metrics."""
    if not ENABLE_DB or CURRENT_SESSION_ID is None:
        return {"error": "Database not available"}

    try:
        from database.metrics_manager import get_metrics_summary
        summary = get_metrics_summary(CURRENT_SESSION_ID)
        return summary or {"error": "No data available"}
    except Exception as e:
        logger.error(f"❌ Error fetching metrics summary: {e}")
        return {"error": str(e)}


class ScanInput(BaseModel):
    sample_path: str
    label: int = 0

@app.post("/scan")
def scan(data: ScanInput, current_user: dict = Depends(get_current_user)):

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
def run_ransomware_pipeline(current_user: dict = Depends(get_current_user)):
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
        run_simulation(n_benign=20, n_ransom_bursts=3, seed=42)

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

        # ── Log to database ────────────────────────────────────────────
        if ENABLE_DB and CURRENT_SESSION_ID is not None:
            try:
                # Log ransomware threat event
                if summary["ransomware"] > 0:
                    log_ransomware_threat(
                        CURRENT_SESSION_ID,
                        summary["ransomware"],
                        f"Detected {summary['ransomware']} ransomware threat(s) in pipeline"
                    )
            except Exception as e:
                logger.warning(f"⚠️  Failed to log ransomware event: {e}")

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


# ─────────────────────────────────────────────────────────────────────────────
# Dual Scan Mode Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def _clear_scan_outputs():
    """Clear output files when switching scan modes."""
    global _PREDICTIONS_LOG, _ALERTS_LOG, _RANSOM_ROOT

    try:
        # Clear predictions_log.csv
        _PREDICTIONS_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(_PREDICTIONS_LOG, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "process_name", "prediction",
                "confidence", "threat_level", "source"
            ])
            writer.writeheader()

        # Clear alerts.log
        with open(_ALERTS_LOG, "w", encoding="utf-8") as f:
            f.write("")

        # Clear honeypot_log.csv
        honeypot_log = _RANSOM_ROOT / "honeypot" / "honeypot_log.csv"
        with open(honeypot_log, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "process_name", "file_path", "operation",
                "entropy", "extension_changed", "write_count",
                "rename_count", "suspicious_score"
            ])
            writer.writeheader()

        logger.info("Output files cleared")
    except Exception as e:
        logger.error(f"Error clearing outputs: {e}")


def _stop_current_scan():
    """Internal: Stop the currently running scan."""
    global _current_scan_thread, _scan_stop_requested, _scan_active, _current_scan_mode

    if _current_scan_thread and _current_scan_thread.is_alive():
        _scan_stop_requested = True
        _scan_event.set()
        _current_scan_thread.join(timeout=5)

    _scan_active = False
    _current_scan_mode = None
    _scan_stop_requested = False


def _run_predictions(source="SIMULATION"):
    """Shared prediction logic for both simulation and system monitoring modes."""
    global _scan_stop_requested, _PREDICTIONS_LOG, _ALERTS_LOG, _RANSOM_ROOT

    from ransomware_module.models.predict_lstm import RansomwareDetector

    det = RansomwareDetector(threshold=0.5)
    det._ensure_loaded()

    live_input = _RANSOM_ROOT / "data" / "live_input.csv"
    predictions = []
    alerts_text = ""

    try:
        with open(live_input, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if _scan_stop_requested:
                    logger.info("Prediction stopped by user request")
                    break

                result = det.predict_dict(row)
                ts = row.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                proc = row.get("process_name", "unknown")
                conf = round(float(result["confidence"]), 4)
                threat = result["threat_level"]
                pred = result["prediction"]

                predictions.append({
                    "timestamp": ts,
                    "process_name": proc,
                    "prediction": pred,
                    "confidence": conf,
                    "threat_level": threat,
                    "source": source,
                })

                if threat in ("WARNING", "CRITICAL"):
                    label = "ransomware" if threat == "CRITICAL" else "suspicious"
                    alerts_text += "=" * 60 + "\n"
                    alerts_text += f"{threat} ALERT\n"
                    alerts_text += f"Timestamp  : {ts}\n"
                    alerts_text += f"Detection  : Early {label} detected\n"
                    alerts_text += f"Process    : {proc}\n"
                    alerts_text += f"Confidence : {conf}\n"
                    alerts_text += f"Source     : {source}\n"
                    alerts_text += "=" * 60 + "\n\n"

    except FileNotFoundError:
        logger.warning(f"live_input.csv not found: {live_input}")
        return

    # Write outputs
    try:
        _PREDICTIONS_LOG.parent.mkdir(parents=True, exist_ok=True)

        with open(_PREDICTIONS_LOG, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "process_name", "prediction",
                "confidence", "threat_level", "source"
            ])
            writer.writeheader()
            writer.writerows(predictions)

        with open(_ALERTS_LOG, "w", encoding="utf-8") as f:
            f.write(alerts_text)

        logger.info(f"Wrote {len(predictions)} predictions with source={source}")
    except Exception as e:
        logger.error(f"Error writing predictions: {e}")


def _run_simulation_pipeline():
    """Background thread: Run simulation pipeline."""
    global _scan_active, _scan_stop_requested

    try:
        logger.info("Starting simulation pipeline...")

        # Step 1: Simulate
        from ransomware_module.honeypot.honeypot_simulator import run_simulation
        run_simulation(n_benign=20, n_ransom_bursts=3, seed=42)

        if _scan_stop_requested:
            logger.info("Simulation stopped by user")
            return

        # Step 2: Extract features
        from ransomware_module.utils.honeypot_feature_extractor import extract
        extract()

        if _scan_stop_requested:
            logger.info("Feature extraction stopped by user")
            return

        # Step 3: Predict
        _run_predictions(source="SIMULATION")

    except Exception as e:
        logger.error(f"Simulation scan error: {e}")
    finally:
        _scan_active = False
        logger.info("Simulation pipeline complete")


def _run_system_monitoring_pipeline():
    """Background thread: Run real system monitoring pipeline."""
    global _scan_active, _scan_stop_requested

    try:
        logger.info("Starting real system monitoring pipeline...")

        # Step 1: Monitor real system
        from ransomware_module.monitor.system_monitor import SystemMonitor
        import getpass

        username = getpass.getuser()
        watch_dirs = [
            f"C:\\Users\\{username}\\Desktop",
            f"C:\\Users\\{username}\\Documents",
            f"C:\\Users\\{username}\\Downloads",
        ]

        monitor = SystemMonitor(
            watch_dirs=watch_dirs,
            duration_seconds=60,
            check_stop_flag=lambda: _scan_stop_requested
        )
        monitor.collect_telemetry()

        if _scan_stop_requested:
            logger.info("System monitoring stopped by user")
            return

        # Step 2: Extract features (same as simulation)
        from ransomware_module.utils.honeypot_feature_extractor import extract
        extract()

        if _scan_stop_requested:
            logger.info("Feature extraction stopped by user")
            return

        # Step 3: Predict
        _run_predictions(source="REAL_SYSTEM_MONITORING")

    except Exception as e:
        logger.error(f"System scan error: {e}")
    finally:
        _scan_active = False
        logger.info("System monitoring pipeline complete")


# ─────────────────────────────────────────────────────────────────────────────
# Honeypot Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

def _clear_honeypot_outputs():
    """Clear honeypot output files when switching modes."""
    honeypot_log = _RANSOM_ROOT / "honeypot" / "honeypot_log.csv"
    honeypot_log.parent.mkdir(parents=True, exist_ok=True)

    # Clear honeypot_log.csv with headers only
    with open(honeypot_log, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "process_name", "file_path", "operation",
            "entropy", "extension_changed", "write_count",
            "rename_count", "suspicious_score"
        ])
        writer.writeheader()
    logger.info("Cleared honeypot_log.csv")


def _stop_current_honeypot_scan():
    """Internal: Stop the currently running honeypot scan."""
    global _honeypot_scan_stop_requested, _honeypot_scan_active, _honeypot_scan_mode, _honeypot_scan_thread

    if _honeypot_scan_thread and _honeypot_scan_thread.is_alive():
        _honeypot_scan_stop_requested = True
        _honeypot_scan_thread.join(timeout=5)

    _honeypot_scan_active = False
    _honeypot_scan_mode = None
    _honeypot_scan_stop_requested = False


def _run_honeypot_simulation_pipeline():
    """Background thread: Run honeypot simulation pipeline."""
    global _honeypot_scan_active, _honeypot_scan_stop_requested

    try:
        logger.info("Starting honeypot simulation pipeline...")

        # Step 1: Run honeypot simulation
        from ransomware_module.honeypot.honeypot_simulator import HoneypotSimulator

        simulator = HoneypotSimulator(mode="simulate")
        simulator.run(n_benign=50, n_ransom_bursts=5, seed=42)

        if _honeypot_scan_stop_requested:
            logger.info("Honeypot simulation stopped by user")
            return

        logger.info("Honeypot simulation complete")

    except Exception as e:
        logger.error(f"Honeypot simulation error: {e}")
    finally:
        _honeypot_scan_active = False
        logger.info("Honeypot simulation pipeline complete")


def _run_honeypot_monitor_pipeline():
    """Background thread: Run real honeypot monitoring pipeline."""
    global _honeypot_scan_active, _honeypot_scan_stop_requested

    try:
        logger.info("Starting real honeypot monitoring pipeline...")
        import getpass

        # Step 1: Create decoy directory and run real monitoring
        from ransomware_module.honeypot.honeypot_simulator import HoneypotSimulator

        username = getpass.getuser()
        decoy_dir = Path(f"C:\\Users\\{username}\\Documents\\honeypot_decoys")

        monitor = HoneypotSimulator(mode="real", decoy_dir=decoy_dir)

        # Run for limited duration (60 seconds) with stop flag support
        import time
        from ransomware_module.honeypot.honeypot_simulator import create_decoy_files, EventLogger, run_real_monitor

        # Create decoy files
        create_decoy_files(decoy_dir, count=10)
        logger.info(f"Created honeypot decoys in: {decoy_dir}")

        # Run monitoring with 60-second timeout
        start_time = datetime.now()
        duration = 60  # seconds

        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            from ransomware_module.honeypot.honeypot_simulator import _HoneypotEventHandler, EventLogger

            event_logger = EventLogger(_HONEYPOT_LOG)
            decoy_paths = list(decoy_dir.glob("*"))

            class _Adapter(FileSystemEventHandler):
                def __init__(self, handler):
                    self._h = handler
                def on_modified(self, event):  self._h.on_modified(event)
                def on_created(self, event):   self._h.on_created(event)
                def on_deleted(self, event):   self._h.on_deleted(event)
                def on_moved(self, event):     self._h.on_moved(event)

            handler = _HoneypotEventHandler(event_logger, decoy_paths)
            adapter = _Adapter(handler)

            observer = Observer()
            observer.schedule(adapter, str(decoy_dir), recursive=False)
            observer.start()

            logger.info(f"Real honeypot monitor active on {decoy_dir}")

            # Monitor for 60 seconds or until stop requested
            while (datetime.now() - start_time).total_seconds() < duration:
                if _honeypot_scan_stop_requested:
                    logger.info("Honeypot monitor stopped by user")
                    break
                time.sleep(1)

            observer.stop()
            observer.join()

        except ImportError:
            logger.warning("watchdog not installed; skipping real monitoring")

        if _honeypot_scan_stop_requested:
            logger.info("Honeypot monitoring stopped by user")
            return

        logger.info("Honeypot monitoring complete")

    except Exception as e:
        logger.error(f"Honeypot monitoring error: {e}")
    finally:
        _honeypot_scan_active = False
        logger.info("Honeypot monitoring pipeline complete")


# ─────────────────────────────────────────────────────────────────────────────
# Dual Scan Mode API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/ransomware/start-scan-simulation")
def start_scan_simulation(current_user: dict = Depends(get_current_user)):
    """Start simulation scan in background thread."""
    global _current_scan_mode, _scan_active, _scan_start_time, _scan_stop_requested, _current_scan_thread

    with _scan_lock:
        # Stop any existing scan
        _stop_current_scan()

        # Clear outputs
        _clear_scan_outputs()

        # Start simulation thread
        _current_scan_mode = "simulation"
        _scan_active = True
        _scan_start_time = datetime.now()
        _scan_stop_requested = False

        thread = threading.Thread(
            target=_run_simulation_pipeline,
            daemon=True
        )
        _current_scan_thread = thread
        thread.start()

    return {
        "status": "started",
        "mode": "simulation",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/ransomware/start-scan-system")
def start_scan_system(current_user: dict = Depends(get_current_user)):
    """Start real system monitoring in background thread."""
    global _current_scan_mode, _scan_active, _scan_start_time, _scan_stop_requested, _current_scan_thread

    with _scan_lock:
        # Stop any existing scan
        _stop_current_scan()

        # Clear outputs
        _clear_scan_outputs()

        # Startystem monitoring thread
        _current_scan_mode = "system"
        _scan_active = True
        _scan_start_time = datetime.now()
        _scan_stop_requested = False

        thread = threading.Thread(
            target=_run_system_monitoring_pipeline,
            daemon=True
        )
        _current_scan_thread = thread
        thread.start()

    return {
        "status": "started",
        "mode": "system",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/ransomware/stop-scan")
def stop_scan(current_user: dict = Depends(get_current_user)):
    """Stop currently running scan."""
    global _scan_stop_requested, _scan_active

    with _scan_lock:
        if _scan_active:
            _scan_stop_requested = True
            _scan_event.set()

    # Wait for thread to finish (max 5s)
    if _current_scan_thread and _current_scan_thread.is_alive():
        _current_scan_thread.join(timeout=5)

    _scan_active = False
    return {"status": "stopped"}


@app.get("/api/ransomware/scan-status")
def scan_status():
    """Get current scan status and progress."""
    global _scan_start_time, _current_scan_mode

    with _scan_lock:
        duration = None
        if _scan_start_time:
            duration = (datetime.now() - _scan_start_time).total_seconds()

        return {
            "active": _scan_active,
            "mode": _current_scan_mode,
            "duration_seconds": duration,
            "stop_requested": _scan_stop_requested,
        }


@app.post("/api/ransomware/scan-real-system")
def scan_real_system():
    """
    Legacy endpoint: Start real system scan (now uses dual-mode system).
    For backward compatibility, this delegates to the new system scan endpoint.
    """
    return start_scan_system()


# ─────────────────────────────────────────────────────────────────────────────
# Honeypot Dual Scan Mode API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/honeypot/start-simulation")
def start_honeypot_simulation(current_user: dict = Depends(get_current_user)):
    """Start honeypot simulation scan in background thread."""
    global _honeypot_scan_mode, _honeypot_scan_active, _honeypot_scan_start_time
    global _honeypot_scan_stop_requested, _honeypot_scan_thread

    with _scan_lock:
        # Stop any existing honeypot scan
        _stop_current_honeypot_scan()

        # Clear honeypot outputs
        _clear_honeypot_outputs()

        # Start simulation thread
        _honeypot_scan_mode = "simulation"
        _honeypot_scan_active = True
        _honeypot_scan_start_time = datetime.now()
        _honeypot_scan_stop_requested = False

        thread = threading.Thread(
            target=_run_honeypot_simulation_pipeline,
            daemon=True
        )
        _honeypot_scan_thread = thread
        thread.start()

    return {
        "status": "started",
        "mode": "simulation",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/honeypot/start-monitor")
def start_honeypot_monitor(current_user: dict = Depends(get_current_user)):
    """Start real honeypot monitoring in background thread."""
    global _honeypot_scan_mode, _honeypot_scan_active, _honeypot_scan_start_time
    global _honeypot_scan_stop_requested, _honeypot_scan_thread

    with _scan_lock:
        # Stop any existing honeypot scan
        _stop_current_honeypot_scan()

        # Clear honeypot outputs
        _clear_honeypot_outputs()

        # Start monitoring thread
        _honeypot_scan_mode = "monitor"
        _honeypot_scan_active = True
        _honeypot_scan_start_time = datetime.now()
        _honeypot_scan_stop_requested = False

        thread = threading.Thread(
            target=_run_honeypot_monitor_pipeline,
            daemon=True
        )
        _honeypot_scan_thread = thread
        thread.start()

    return {
        "status": "started",
        "mode": "monitor",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/honeypot/stop")
def stop_honeypot_scan(current_user: dict = Depends(get_current_user)):
    """Stop currently running honeypot scan."""
    global _honeypot_scan_stop_requested, _honeypot_scan_active

    with _scan_lock:
        if _honeypot_scan_active:
            _honeypot_scan_stop_requested = True
            _scan_event.set()

    # Wait for thread to finish (max 5s)
    if _honeypot_scan_thread and _honeypot_scan_thread.is_alive():
        _honeypot_scan_thread.join(timeout=5)

    _honeypot_scan_active = False
    return {"status": "stopped"}


@app.get("/api/honeypot/scan-status")
def honeypot_scan_status(current_user: dict = Depends(get_current_user)):
    """Get current honeypot scan status and progress."""
    global _honeypot_scan_start_time, _honeypot_scan_mode

    with _scan_lock:
        duration = None
        if _honeypot_scan_start_time:
            duration = (datetime.now() - _honeypot_scan_start_time).total_seconds()

        return {
            "active": _honeypot_scan_active,
            "mode": _honeypot_scan_mode,
            "duration_seconds": duration,
            "stop_requested": _honeypot_scan_stop_requested,
        }


@app.get("/api/honeypot/log")
def get_honeypot_log(current_user: dict = Depends(get_current_user)):
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

    # ── Log to database ────────────────────────────────────────────
    if ENABLE_DB and CURRENT_SESSION_ID is not None:
        try:
            # Log honeypot interactions
            critical_count = summary["critical"]
            if critical_count > 0:
                log_honeypot_interaction(
                    CURRENT_SESSION_ID,
                    critical_count,
                    f"Detected {critical_count} critical honeypot interaction(s)"
                )
        except Exception as e:
            logger.warning(f"⚠️  Failed to log honeypot event: {e}")

    return {"events": rows, "summary": summary}


# ---------------------------------------------------------------------------
# Port scan — localhost auto-scan endpoint
# ---------------------------------------------------------------------------

_NMAP_EXE = r"C:\Program Files (x86)\Nmap\nmap.exe"
if not os.path.exists(_NMAP_EXE):
    _NMAP_EXE = "nmap"

# Quick risk lookup by port number
_PORT_RISK = {
    # HIGH
    21: "HIGH", 22: "HIGH", 23: "HIGH", 25: "HIGH",
    110: "HIGH", 135: "HIGH", 137: "HIGH", 138: "HIGH",
    139: "HIGH", 445: "HIGH", 512: "HIGH", 513: "HIGH",
    514: "HIGH", 1433: "HIGH", 1434: "HIGH", 1521: "HIGH",
    2049: "HIGH", 3389: "HIGH", 4444: "HIGH", 5900: "HIGH",
    6667: "HIGH", 8443: "HIGH",
    # MEDIUM
    53: "MEDIUM", 80: "MEDIUM", 443: "MEDIUM", 587: "MEDIUM",
    143: "MEDIUM", 993: "MEDIUM", 995: "MEDIUM", 3000: "MEDIUM",
    3001: "MEDIUM", 5000: "MEDIUM", 7000: "MEDIUM", 8000: "MEDIUM",
    8080: "MEDIUM", 8888: "MEDIUM", 9000: "MEDIUM", 9090: "MEDIUM",
}


def _nmap_parse(xml_path: str) -> list:
    """Parse nmap XML and return [{ port, service, risk }]."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return []

    ports = []
    for host in root.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portnum = int(port_el.get("portid", 0))
            svc_el  = port_el.find("service")
            service = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
            risk    = _PORT_RISK.get(portnum, "LOW")
            ports.append({"port": portnum, "service": service, "risk": risk})

    return sorted(ports, key=lambda x: (
        0 if x["risk"] == "HIGH" else 1 if x["risk"] == "MEDIUM" else 2,
        x["port"]
    ))


@app.post("/api/portscan/scan")
def portscan_localhost(current_user: dict = Depends(get_current_user)):
    """Run Nmap on localhost and return open ports with AI risk levels."""
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    try:
        proc = subprocess.run(
            [_NMAP_EXE, "-sV", "--open", "-T4", "-oX", xml_path, "127.0.0.1"],
            capture_output=True, text=True, timeout=120
        )
        if proc.returncode != 0:
            return {
                "status": "error",
                "message": f"Nmap failed: {proc.stderr.strip() or 'non-zero exit'}",
                "ports": [],
            }

        ports = _nmap_parse(xml_path)
        high   = sum(1 for p in ports if p["risk"] == "HIGH")
        medium = sum(1 for p in ports if p["risk"] == "MEDIUM")
        low    = sum(1 for p in ports if p["risk"] == "LOW")

        # ── Log to database ────────────────────────────────────────────
        if ENABLE_DB and CURRENT_SESSION_ID is not None:
            try:
                # Log each open port
                for port in ports:
                    log_port_open(
                        CURRENT_SESSION_ID,
                        port.get("port", "unknown"),
                        port.get("risk", "MEDIUM"),
                        f"Service: {port.get('service', 'unknown')}"
                    )
            except Exception as e:
                logger.warning(f"⚠️  Failed to log port events: {e}")

        return {
            "status":     "success",
            "host":       "127.0.0.1",
            "scan_time":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total":      len(ports),
            "high":       high,
            "medium":     medium,
            "low":        low,
            "ports":      ports,
        }

    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "Nmap timed out after 120 s.", "ports": []}
    except Exception as e:
        return {"status": "error", "message": str(e), "ports": []}
    finally:
        try:
            os.remove(xml_path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Security Metrics API — Real-time threat activity aggregation
# ---------------------------------------------------------------------------

@app.get("/api/security-metrics")
def get_security_metrics(current_user: dict = Depends(get_current_user)):
    """
    Aggregate and return latest security metrics from scan outputs.
    Reads: predictions_log.csv, honeypot_log.csv
    Returns: Latest counts per scan cycle
    """
    try:
        metrics = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "ransomware": 0,
            "port_scan": 0,
            "honeypot": 0,
        }

        # Read ransomware predictions (count RANSOMWARE predictions)
        if _PREDICTIONS_LOG.exists():
            try:
                df = pd.read_csv(_PREDICTIONS_LOG)
                if not df.empty and "prediction" in df.columns:
                    # Count RANSOMWARE predictions from latest scan
                    ransomware_count = len(df[df["prediction"] == "RANSOMWARE"])
                    metrics["ransomware"] = int(ransomware_count)
            except Exception as e:
                logger.warning(f"Error reading predictions: {e}")

        # Read honeypot log (count CRITICAL + HIGH severity events)
        if _HONEYPOT_LOG.exists():
            try:
                df = pd.read_csv(_HONEYPOT_LOG)
                if not df.empty and "suspicious_score" in df.columns:
                    # Count events with suspicious_score >= 0.4 (WARNING or CRITICAL)
                    df["suspicious_score"] = pd.to_numeric(df["suspicious_score"], errors="coerce").fillna(0)
                    honeypot_count = len(df[df["suspicious_score"] >= 0.4])
                    metrics["honeypot"] = int(honeypot_count)
            except Exception as e:
                logger.warning(f"Error reading honeypot log: {e}")

        # Port scan count from port scan endpoint summary
        # For now, we'll count HIGH + CRITICAL risk ports if running nmap
        # This assumes port_scan_results.csv exists or we count from latest scan
        metrics["port_scan"] = 0  # Default to 0, can be enhanced based on port scan CSV

        # Calculate total
        metrics["total"] = metrics["ransomware"] + metrics["port_scan"] + metrics["honeypot"]

        return metrics

    except Exception as e:
        logger.error(f"Error in get_security_metrics: {e}")
        return {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "ransomware": 0,
            "port_scan": 0,
            "honeypot": 0,
            "total": 0,
            "error": str(e)
        }
