"""Rebuild the bundled synthetic sample database.

usage: PYTHONPATH=src python scripts/build_sample_db.py
"""

from __future__ import annotations

from pathlib import Path

from rawmcp.sampledb import build_sample_db, content_digest

if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "src" / "rawmcp" / "data" / "sample.db"
    build_sample_db(target)
    print(f"wrote {target.name} ({target.stat().st_size} bytes, content sha256 {content_digest(target)[:16]})")
