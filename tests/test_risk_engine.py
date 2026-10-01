from pathlib import Path

from src.risk_engine import calculate_risk_score, categorize_risk, load_thresholds


def test_risk_score_and_category():
    thresholds = load_thresholds(Path(__file__).resolve().parents[1] / "config" / "detection_thresholds.yaml")
    event = {
        "subdomain_length": 80,
        "entropy": 4.5,
        "queries_per_minute": 80,
        "unique_subdomains_per_parent_domain": 60,
        "parent_domain": "lab-sync.test",
        "suspicious_process": True,
    }
    score = calculate_risk_score(event, thresholds)
    assert score >= 80
    assert categorize_risk(score, thresholds) == "Critical"
