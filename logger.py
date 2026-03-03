"""
CTI Logger — structured per-agent reasoning logs with timestamps and latency.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

import config


def setup_logging(*, console_level: int = logging.INFO) -> Path:
    """
    Configure the mad_cti logger to write to both console and a timestamped
    log file under logs/.

    Returns the path to the log file.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = config.LOGS_DIR / f"pipeline_run_{timestamp}.log"

    logger = logging.getLogger("mad_cti")
    logger.setLevel(logging.DEBUG)

    # Avoid duplicate handlers on re-init
    if logger.handlers:
        logger.handlers.clear()

    # ── File handler: captures everything (DEBUG+) ─────────────────────
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(fh)

    # ── Console handler: summary level ─────────────────────────────────
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(console_level)
    ch.setFormatter(
        logging.Formatter("%(levelname)s | %(message)s")
    )
    logger.addHandler(ch)

    logger.info("Logging initialized → %s", log_file)
    return log_file
