"""Explainable DNS risk scoring engine."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


def load_thresholds(path: str | Path) -> dict:
    """Load YAML thresholds for detection logic."""
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def categorize_risk(score: float, thresholds: dict) -> str:
    """Convert a numeric risk score to a category."""
    low_max = thresholds.get("categories", {}).get("low_max", 29)
    medium_max = thresholds.get("categories", {}).get("medium_max", 59)
    high_max = thresholds.get("categories", {}).get("high_max", 79)

    if score <= low_max:
        return "Low"
    if score <= medium_max:
        return "Medium"
    if score <= high_max:
        return "High"
    return "Critical"


def calculate_risk_score(event: dict, thresholds: dict) -> int:
    """Return a simple explainable DNS risk score."""
    score = 0
    risk_cfg = thresholds.get("risk", {})

    if event.get("subdomain_length", 0) > risk_cfg.get("long_subdomain_threshold", 35):
        score += 20
    if event.get("entropy", 0.0) > risk_cfg.get("entropy_threshold", 3.4):
        score += 25
    if event.get("queries_per_minute", 0) > risk_cfg.get("query_rate_threshold", 40):
        score += 20
    if event.get("unique_subdomains_per_parent_domain", 0) > risk_cfg.get("unique_subdomain_threshold", 30):
        score += 20
    if event.get("parent_domain") == "lab-sync.test":
        score += 10
    if event.get("suspicious_process", False):
        score += 25

    return score
