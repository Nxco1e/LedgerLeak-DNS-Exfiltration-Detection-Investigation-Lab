"""Utility helpers for project generation and analysis."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def repo_root() -> Path:
    """Return the repository root path."""
    return Path(__file__).resolve().parents[1]


def isoformat_utc(dt: datetime) -> str:
    """Return an ISO 8601 UTC timestamp string."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    """Write a CSV file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_json(path: Path, payload: list[dict] | dict) -> None:
    """Write a JSON payload to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
