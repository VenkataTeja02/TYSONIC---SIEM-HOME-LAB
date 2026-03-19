"""
SIEM Logging Configuration — v1.0
Central logging setup for all SIEM modules.
Replaces all print() calls with structured, levelled log output.

Usage in any module:
    from siem_logger import get_logger
    logger = get_logger(__name__)
    logger.info("Alert stored")
    logger.warning("ES index not found")
    logger.error("Worker crashed: %s", e)
    logger.critical("Cannot connect to Elasticsearch")
"""

import logging
import logging.handlers
import sys
from pathlib import Path

# ── Log levels by component ───────────────────────────────────────────────────
# Override per-module via environment: SIEM_LOG_LEVEL=DEBUG
import os
_DEFAULT_LEVEL = os.environ.get("SIEM_LOG_LEVEL", "INFO").upper()

# ── Log file location ─────────────────────────────────────────────────────────
_LOG_DIR  = Path(os.environ.get("SIEM_LOG_DIR", "./siem_data/logs"))
_LOG_FILE = _LOG_DIR / "siem.log"

# ── Formatters ────────────────────────────────────────────────────────────────
_CONSOLE_FMT = logging.Formatter(
    fmt   = "%(asctime)s  %(levelname)-8s  %(name)-22s  %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
)
_FILE_FMT = logging.Formatter(
    fmt   = "%(asctime)s  %(levelname)-8s  %(name)s  [%(filename)s:%(lineno)d]  %(message)s",
    datefmt = "%Y-%m-%dT%H:%M:%S",
)


def _build_root_logger() -> logging.Logger:
    """
    Configure the root logger once.
    - Console handler  → stdout, INFO+
    - Rotating file    → siem_data/logs/siem.log, DEBUG+, 10MB × 5 backups
    """
    root = logging.getLogger("siem")
    if root.handlers:
        return root   # already configured — don't add duplicate handlers

    root.setLevel(logging.DEBUG)

    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(getattr(logging, _DEFAULT_LEVEL, logging.INFO))
    ch.setFormatter(_CONSOLE_FMT)
    root.addHandler(ch)

    # Rotating file
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            _LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_FILE_FMT)
        root.addHandler(fh)
    except Exception as e:
        root.warning("Could not create log file %s: %s", _LOG_FILE, e)

    # Silence noisy third-party loggers
    for noisy in ("elasticsearch", "urllib3", "werkzeug"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return root


# Initialise on import
_build_root_logger()


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the 'siem' namespace.
    Usage:
        logger = get_logger(__name__)
    """
    # Strip leading path separators and convert to dotted namespace
    clean = name.lstrip("./").replace("/", ".").replace("\\", ".")
    # Always nest under 'siem.' so our handlers pick it up
    if not clean.startswith("siem"):
        clean = f"siem.{clean}"
    return logging.getLogger(clean)