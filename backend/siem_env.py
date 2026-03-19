"""
SIEM Secrets / Environment Configuration — v1.0
Loads configuration from a .env file into os.environ.

Uses python-dotenv if installed, otherwise falls back to a built-in parser.
Create a .env file in the project root (never commit it to git).
Copy .env.example to .env and fill in your values.

Usage:
    from siem_env import load_env
    load_env()   # call once at the top of app.py before reading os.environ
"""

import os
import re
from pathlib import Path


def _builtin_dotenv_load(env_path: Path):
    """
    Minimal .env parser — supports:
      KEY=value
      KEY="quoted value"
      KEY='single quoted'
      # comments
      export KEY=value
    Does NOT overwrite existing env vars (matches python-dotenv default).
    """
    if not env_path.exists():
        return

    with open(env_path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            # Skip blanks and comments
            if not line or line.startswith("#"):
                continue
            # Strip optional 'export ' prefix
            line = re.sub(r"^export\s+", "", line)
            # Split on first '='
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            # Remove surrounding quotes
            if len(val) >= 2 and val[0] in ('"', "'") and val[-1] == val[0]:
                val = val[1:-1]
            # Don't overwrite existing env vars
            if key and key not in os.environ:
                os.environ[key] = val


def load_env(env_file: str = ".env"):
    """
    Load environment variables from .env file.
    Falls back to built-in parser if python-dotenv is not installed.
    """
    env_path = Path(env_file)
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=env_path, override=False)
    except ImportError:
        _builtin_dotenv_load(env_path)