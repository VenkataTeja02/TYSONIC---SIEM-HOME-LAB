#!/usr/bin/env python3
"""
reset_siem.py — TYSONIC SIEM
──────────────────────────────────
Clears all collected runtime data:
  - Alerts (SQLite DB, JSON, CSV)
  - Audit log
  - Incidents
  - Blocked IPs
  - Playbook execution log
  - Evidence files
  - HTML reports
  - SIEM log files
  - UEBA baselines (if present)
  - Rate tracker memory (in-process — resets on restart)

Does NOT touch:
  - users.json     (accounts and passwords kept)
  - config.json    (Telegram settings kept)
  - ingest_api_key.txt  (API key kept)
  - .env           (secrets kept)
  - Source code    (*.py, *.html)

Usage:
  python3 reset_siem.py           # interactive (asks confirmation)
  python3 reset_siem.py --force   # no prompt (use in scripts)
  python3 reset_siem.py --dry-run # show what would be cleared, don't clear
"""

import os
import sys
import json
import shutil
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime, timezone

# ── Config ────────────────────────────────────────────────────────────────────

DATA_DIR = Path("./siem_data")

# Files to overwrite with empty content (keep file, clear contents)
CLEAR_FILES = {
    DATA_DIR / "alerts.json":        "[]",
    DATA_DIR / "alerts.csv":         "",        # recreated with header on next alert
    DATA_DIR / "audit.jsonl":        "",
    DATA_DIR / "incidents.json":     "[]",
    DATA_DIR / "blocked_ips.json":   "[]",
    DATA_DIR / "playbook_log.jsonl": "",
    DATA_DIR / "ueba_baselines.json":"{}",
}

# Directories to wipe completely (all files inside deleted)
CLEAR_DIRS = {
    DATA_DIR / "reports":   "HTML incident reports",
    DATA_DIR / "evidence":  "Collected evidence files",
    DATA_DIR / "logs":      "SIEM log files",
}

# SQLite databases to wipe (tables cleared, schema kept)
CLEAR_DBS = {
    DATA_DIR / "alerts.db": ["alerts"],
}

# Files/dirs to NEVER touch
PROTECTED = {
    DATA_DIR / "users.json",
    DATA_DIR / "config.json",
    DATA_DIR / "ingest_api_key.txt",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def skip(msg): print(f"  {DIM}–{RESET}  {DIM}{msg}{RESET}")
def warn(msg): print(f"  {YELLOW}!{RESET}  {YELLOW}{msg}{RESET}")
def err(msg):  print(f"  {RED}✗{RESET}  {RED}{msg}{RESET}")

def size_str(path: Path) -> str:
    """Human-readable size of a file or directory."""
    try:
        if path.is_dir():
            total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
        else:
            total = path.stat().st_size
        if total < 1024:         return f"{total} B"
        elif total < 1_048_576:  return f"{total/1024:.1f} KB"
        else:                    return f"{total/1_048_576:.1f} MB"
    except Exception:
        return "? B"

def count_str(path: Path) -> str:
    """Count items in a file or directory."""
    try:
        if path.is_dir():
            n = len(list(path.rglob("*")))
            return f"{n} file{'s' if n != 1 else ''}"
        if path.suffix == ".db":
            return ""
        content = path.read_text(errors="replace").strip()
        if not content:
            return "empty"
        if content.startswith("["):
            data = json.loads(content)
            return f"{len(data)} record{'s' if len(data) != 1 else ''}"
        lines = [l for l in content.splitlines() if l.strip()]
        return f"{len(lines)} line{'s' if len(lines) != 1 else ''}"
    except Exception:
        return ""


# ── Main reset logic ──────────────────────────────────────────────────────────

def preview():
    """Show what would be cleared without doing anything."""
    print(f"\n{BOLD}{CYAN}  SIEM DATA PREVIEW{RESET}")
    print(f"  {DIM}{'─'*50}{RESET}\n")

    total_size = 0

    print(f"  {BOLD}Files to clear:{RESET}")
    for path, _ in CLEAR_FILES.items():
        if path.exists():
            c = count_str(path)
            s = size_str(path)
            total_size += path.stat().st_size if path.exists() else 0
            print(f"    {YELLOW}○{RESET}  {path.name:<30} {c:<18} {DIM}{s}{RESET}")
        else:
            skip(f"  {path.name} (doesn't exist yet)")

    print(f"\n  {BOLD}Databases to wipe:{RESET}")
    for path, tables in CLEAR_DBS.items():
        if path.exists():
            s = size_str(path)
            total_size += path.stat().st_size
            try:
                conn = sqlite3.connect(path)
                rows = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                conn.close()
                print(f"    {YELLOW}○{RESET}  {path.name:<30} {rows} alert rows          {DIM}{s}{RESET}")
            except Exception:
                print(f"    {YELLOW}○{RESET}  {path.name:<30}                        {DIM}{s}{RESET}")
        else:
            skip(f"  {path.name} (doesn't exist yet)")

    print(f"\n  {BOLD}Directories to wipe:{RESET}")
    for path, desc in CLEAR_DIRS.items():
        if path.exists():
            c = count_str(path)
            s = size_str(path)
            print(f"    {YELLOW}○{RESET}  {path.name:<30} {c:<18} {DIM}{s}{RESET}")
        else:
            skip(f"  {path.name}/ (doesn't exist yet)")

    print(f"\n  {BOLD}Protected (never touched):{RESET}")
    for path in PROTECTED:
        if path.exists():
            ok(f"{path.name} — kept")
        else:
            skip(f"{path.name} — doesn't exist")

    print(f"\n  {DIM}{'─'*50}{RESET}")
    if total_size > 0:
        if total_size < 1_048_576:
            ts = f"{total_size/1024:.1f} KB"
        else:
            ts = f"{total_size/1_048_576:.1f} MB"
        print(f"  Total data that would be cleared: {BOLD}{ts}{RESET}\n")


def reset(dry_run: bool = False):
    """Perform the actual reset."""
    print(f"\n{BOLD}{CYAN}  CLEARING SIEM DATA{RESET}")
    print(f"  {DIM}{'─'*50}{RESET}\n")

    cleared = 0
    skipped = 0

    # ── 1. Clear files ────────────────────────────────────────────────────────
    print(f"  {BOLD}Clearing files...{RESET}")
    for path, empty_val in CLEAR_FILES.items():
        if path in PROTECTED:
            skip(f"{path.name} — protected")
            skipped += 1
            continue
        if not path.exists():
            skip(f"{path.name} — doesn't exist")
            skipped += 1
            continue
        if not dry_run:
            try:
                path.write_text(empty_val)
                ok(f"{path.name}")
                cleared += 1
            except Exception as e:
                err(f"{path.name} — {e}")
        else:
            ok(f"{path.name} {DIM}(dry run){RESET}")
            cleared += 1

    # ── 2. Wipe SQLite databases ──────────────────────────────────────────────
    print(f"\n  {BOLD}Wiping databases...{RESET}")
    for path, tables in CLEAR_DBS.items():
        if not path.exists():
            skip(f"{path.name} — doesn't exist")
            skipped += 1
            continue
        if not dry_run:
            try:
                conn = sqlite3.connect(path)
                for table in tables:
                    conn.execute(f"DELETE FROM {table}")
                    conn.execute("VACUUM")
                conn.commit()
                conn.close()
                ok(f"{path.name} — all rows deleted")
                cleared += 1
            except Exception as e:
                err(f"{path.name} — {e}")
        else:
            ok(f"{path.name} {DIM}(dry run){RESET}")
            cleared += 1

    # ── 3. Wipe directories ───────────────────────────────────────────────────
    print(f"\n  {BOLD}Wiping directories...{RESET}")
    for path, desc in CLEAR_DIRS.items():
        if not path.exists():
            skip(f"{path.name}/ — doesn't exist")
            skipped += 1
            continue
        if not dry_run:
            try:
                shutil.rmtree(path)
                path.mkdir(parents=True, exist_ok=True)  # recreate empty dir
                ok(f"{path.name}/ — {desc} cleared")
                cleared += 1
            except Exception as e:
                err(f"{path.name}/ — {e}")
        else:
            ok(f"{path.name}/ {DIM}(dry run){RESET}")
            cleared += 1

    # ── 4. Write reset log entry ──────────────────────────────────────────────
    if not dry_run:
        try:
            audit_path = DATA_DIR / "audit.jsonl"
            entry = {
                "ts":     datetime.now(timezone.utc).isoformat(),
                "action": "siem_reset",
                "user":   "reset_script",
                "detail": f"Full SIEM data reset via reset_siem.py"
            }
            with open(audit_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    print(f"\n  {DIM}{'─'*50}{RESET}")
    if dry_run:
        print(f"  {YELLOW}Dry run complete — nothing was changed{RESET}")
    else:
        print(f"  {GREEN}{BOLD}Reset complete!{RESET}  {cleared} items cleared, {skipped} skipped")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Reset TYSONIC SIEM runtime data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--force",   action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be cleared without clearing")
    args = parser.parse_args()

    print(f"\n{BOLD}{RED}  ╔══════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{RED}  ║      TYSONIC SIEM — DATA RESET       ║{RESET}")
    print(f"{BOLD}{RED}  ╚══════════════════════════════════════╝{RESET}")

    if not DATA_DIR.exists():
        warn(f"siem_data/ directory not found at {DATA_DIR.resolve()}")
        warn("Run this script from the same directory as app.py")
        sys.exit(1)

    # Always show preview first
    preview()

    if args.dry_run:
        reset(dry_run=True)
        return

    if not args.force:
        print(f"  {BOLD}{RED}⚠  This will permanently delete all collected SIEM data.{RESET}")
        print(f"  {DIM}Users, config, and API keys are NOT affected.{RESET}\n")
        try:
            answer = input(f"  Type {BOLD}RESET{RESET} to confirm, or press Enter to cancel: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {YELLOW}Cancelled.{RESET}\n")
            sys.exit(0)

        if answer != "RESET":
            print(f"\n  {YELLOW}Cancelled — nothing was changed.{RESET}\n")
            sys.exit(0)

    reset(dry_run=False)
    print(f"  {DIM}Restart app.py to begin fresh data collection.{RESET}\n")


if __name__ == "__main__":
    main()
