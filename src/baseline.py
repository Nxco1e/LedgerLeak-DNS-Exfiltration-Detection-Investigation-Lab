"""Baseline calculations for endpoint DNS behavior."""

from __future__ import annotations

import math
from typing import Any

import pandas as pd


def calculate_host_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """Create baseline z-score style summary for each host."""
    if df.empty:
        return df

    aggregate = {
        "avg_queries_per_minute": ("queries_per_minute", "mean"),
        "avg_query_length": ("full_domain_length", "mean"),
        "avg_entropy": ("entropy", "mean"),
        "nxdomain_percentage": ("nxdomain_ratio", "mean"),
    }

    if "query_name" in df.columns:
        aggregate["unique_domains_per_hour"] = ("query_name", "nunique")
    else:
        aggregate["unique_domains_per_hour"] = ("queries_per_minute", "count")

    baseline = df.groupby("host", as_index=False).agg(**aggregate)
    return baseline


def zscore(value: float, baseline_value: float, baseline_stddev: float) -> float:
    """Calculate a z-score if variance is available, else return 0.0."""
    if baseline_stddev == 0:
        return 0.0
    return (value - baseline_value) / baseline_stddev


def compare_to_baseline(df: pd.DataFrame, baseline: pd.DataFrame) -> pd.DataFrame:
    """Compare current DNS values against endpoint baselines."""
    if df.empty:
        return df

    host_baseline = baseline.copy()
    result = df.merge(host_baseline, on="host", how="left")
    result["query_length_z"] = result.apply(
        lambda row: zscore(row["full_domain_length"], row["avg_query_length"], max(row.get("query_length_stddev", 0.0), 1.0)),
        axis=1,
    )
    result["entropy_z"] = result.apply(
        lambda row: zscore(row["entropy"], row["avg_entropy"], max(row.get("entropy_stddev", 0.0), 1.0)),
        axis=1,
    )
    return result
