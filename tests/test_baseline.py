import pandas as pd

from src.baseline import calculate_host_baseline, zscore


def test_host_baseline_and_zscore():
    df = pd.DataFrame(
        [
            {"host": "FIN-WS-014", "queries_per_minute": 40, "full_domain_length": 60, "entropy": 2.8, "nxdomain_ratio": 0.01},
            {"host": "FIN-WS-014", "queries_per_minute": 45, "full_domain_length": 70, "entropy": 3.0, "nxdomain_ratio": 0.02},
            {"host": "FIN-WS-022", "queries_per_minute": 12, "full_domain_length": 25, "entropy": 1.5, "nxdomain_ratio": 0.005},
        ]
    )
    baseline = calculate_host_baseline(df)
    assert "avg_queries_per_minute" in baseline.columns
    assert zscore(5, 3, 1) == 2.0
