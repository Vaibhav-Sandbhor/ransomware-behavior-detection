"""
Central configuration loader for the MAD-CTI system.
Reads settings from .env file and exposes them as module-level constants.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# -- Paths --
PROJECT_ROOT = Path(__file__).parent.resolve()
OUTPUT_DIR = PROJECT_ROOT / "output"
LOGS_DIR = PROJECT_ROOT / "logs"
SAMPLE_DATASET_PATH = PROJECT_ROOT / "sample_dataset.json"

# Ensure output directories exist
OUTPUT_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# -- Environment Variables --
load_dotenv(PROJECT_ROOT / ".env")

# Ollama runs locally — no API key needed
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
MODEL_NAME: str = os.getenv("MODEL_NAME", "llama3.2")
MAX_TOKENS: int = int(os.getenv("MAX_TOKENS", "2048"))

# -- Validation --
def validate_config() -> None:
    """Check that Ollama is reachable."""
    import requests
    try:
        resp = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        resp.raise_for_status()
        models = [m["name"] for m in resp.json().get("models", [])]
        # Check if the configured model is available (handle tag suffixes)
        model_found = any(MODEL_NAME in m for m in models)
        if not model_found:
            print(f"[WARNING] Model '{MODEL_NAME}' not found in Ollama.")
            print(f"  Available models: {models}")
            print(f"  Run: ollama pull {MODEL_NAME}")
        else:
            print(f"[OK] Ollama is running. Model '{MODEL_NAME}' is available.")
    except requests.ConnectionError:
        raise EnvironmentError(
            "Cannot connect to Ollama at " + OLLAMA_BASE_URL + ". "
            "Make sure Ollama is running (it starts automatically after install)."
        )
