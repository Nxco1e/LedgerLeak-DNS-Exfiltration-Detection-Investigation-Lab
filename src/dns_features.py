"""Feature extraction and DNS analysis helpers."""

from __future__ import annotations

import logging
from typing import Iterable, Sequence

import pandas as pd

from .entropy import character_ratio, shannon_entropy

logger = logging.getLogger(__name__)


def parse_domain_labels(query_name: str) -> list[str]:
    """Return a clean list of DNS labels without trailing root dot."""
    if not query_name:
        return []
    normalized = query_name.strip().rstrip(".")
    return [label for label in normalized.split(".") if label]


def extract_parent_and_subdomain(query_name: str, parent_domain: str | None = None) -> tuple[str, str]:
    """Extract the parent domain and subdomain candidate from a full query."""
    labels = parse_domain_labels(query_name)
    if not labels:
        return "", ""

    if parent_domain:
        normalized_parent = parent_domain.strip().rstrip(".")
        if query_name.rstrip(".").lower().endswith(normalized_parent.lower()):
            subdomain = query_name.rstrip(".")[: -len(normalized_parent) - 1].split(".")[-1]
            if subdomain:
                return normalized_parent, subdomain
            return normalized_parent, ""

    if len(labels) >= 2:
        return ".".join(labels[-2:]), labels[0] if len(labels) > 2 else ""
    return ".".join(labels), ""


def calculate_dns_features(events: pd.DataFrame | Iterable[dict]) -> pd.DataFrame:
    """Compute DNS analysis features for a dataset of query records."""
    df = pd.DataFrame(events) if not isinstance(events, pd.DataFrame) else events.copy()
    if df.empty:
        return df

    df = df.copy()
    df["query_name"] = df.get("query_name", pd.Series(["" for _ in range(len(df))], index=df.index))
    df["query_name"] = df["query_name"].fillna("")
    df["parent_domain"] = df.get("parent_domain", pd.Series(["" for _ in range(len(df))], index=df.index))

    timestamp_values = df.get("timestamp")
    if timestamp_values is None:
        timestamp_values = pd.Series([pd.Timestamp.utcnow() for _ in range(len(df))], index=df.index)
    df["timestamp"] = pd.to_datetime(timestamp_values, utc=True)

    df["src_ip"] = df.get("src_ip", pd.Series(["" for _ in range(len(df))], index=df.index))

    df["labels"] = df["query_name"].apply(parse_domain_labels)
    df["num_labels"] = df["labels"].apply(len)
    df["full_domain_length"] = df["query_name"].str.len()

    def compute_subdomain(row):
        query_name = str(row["query_name"]).rstrip(".")
        parent_domain = str(row.get("parent_domain", ""))
        if parent_domain:
            parent_domain_norm = parent_domain.rstrip(".")
            if query_name.lower().endswith(parent_domain_norm.lower()):
                remainder = query_name[: -len(parent_domain_norm) - 1]
                if remainder:
                    return remainder
        labels = parse_domain_labels(query_name)
        if len(labels) > 2:
            return ".".join(labels[:-2])
        return labels[0] if len(labels) > 1 else query_name

    df["subdomain"] = df.apply(compute_subdomain, axis=1)
    df["subdomain_length"] = df["subdomain"].str.len()
    df["entropy"] = df["subdomain"].apply(shannon_entropy)
    df["numeric_ratio"] = df["subdomain"].apply(lambda value: character_ratio(value, "numeric"))
    df["alphabetic_ratio"] = df["subdomain"].apply(lambda value: character_ratio(value, "alphabetic"))
    df["unique_char_ratio"] = df["subdomain"].apply(lambda value: character_ratio(value, "unique"))

    ip_counts = df.groupby("src_ip").size().to_dict()
    df["query_frequency_by_ip"] = df["src_ip"].map(ip_counts)

    parent_unique_counts = df.groupby("parent_domain")["query_name"].nunique().to_dict()
    df["unique_subdomains_per_parent_domain"] = df["parent_domain"].map(parent_unique_counts)

    parent_domain_average = df.groupby("parent_domain")["subdomain_length"].mean().to_dict()
    df["average_subdomain_length_by_parent"] = df["parent_domain"].map(parent_domain_average)

    minute_counts = (
        df.groupby(["src_ip", pd.Grouper(key="timestamp", freq="min")])
        .size()
        .reset_index(name="queries_per_minute")
    )
    minute_counts.columns = ["src_ip", "timestamp", "queries_per_minute"]
    df = df.merge(minute_counts, on=["src_ip", "timestamp"], how="left")

    df["queries_per_minute"] = df["queries_per_minute"].fillna(1)
    df["nxdomain_ratio"] = 0.0
    if "rcode_name" in df.columns:
        df["nxdomain_ratio"] = df["rcode_name"].eq("NXDOMAIN").astype(float)

    return df


def summarize_by_endpoint(df: pd.DataFrame) -> pd.DataFrame:
    """Create a compact summary for each endpoint."""
    required = {"src_ip", "host", "parent_domain", "query_name"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns for summary: {sorted(missing)}")

    summary = (
        df.groupby(["host", "src_ip", "parent_domain"], as_index=False)
        .agg(
            query_count=("query_name", "size"),
            avg_query_length=("full_domain_length", "mean"),
            avg_entropy=("entropy", "mean"),
            unique_subdomains=("query_name", "nunique"),
            max_subdomain_length=("subdomain_length", "max"),
        )
    )
    return summary
