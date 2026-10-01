"""Generate synthetic DNS telemetry for the LedgerLeak lab."""

from __future__ import annotations

import csv
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.dns_features import calculate_dns_features
from src.utils import isoformat_utc, repo_root, write_csv


HOSTS = {
    "FIN-WS-014": {"ip": "10.20.14.37", "user": "npatel"},
    "FIN-WS-022": {"ip": "10.20.14.41", "user": "mchen"},
    "HR-WS-007": {"ip": "10.20.10.12", "user": "rlopez"},
    "IT-ADMIN-01": {"ip": "10.20.20.17", "user": "jreed"},
    "DC-01": {"ip": "10.20.0.10", "user": "svc_backup"},
}

NORMAL_DOMAINS = [
    "microsoft.com",
    "office.com",
    "windowsupdate.com",
    "github.com",
    "google.com",
    "cloudflare.com",
    "outlook.com",
    "dropbox.com",
    "adobe.com",
    "amazonaws.com",
    "northstar.local",
    "finance.northstar.local",
    "erp.northstar.local",
    "sharepoint.northstar.local",
    "svc.finance.northstar.local",
]

LAB_PARENT = "lab-sync.test"
SUSPICIOUS_SUBDOMAINS = [
    "4d6f636b44617461",
    "6a756e696f72416e616c797374",
    "3132333435363738",
    "42616e6b4461746150726f66696c65",
    "4f5243452d696e666f",
    "66696e616e63652d6578706f7274",
    "5a65726f67656e657261746564",
    "4c65646765724c65616b",
    "736d617274546f6b656e",
    "4d6f72652c4d6f6c696e6f",
]


def build_normal_query(host: str, timestamp: datetime, idx: int) -> dict:
    domain = random.choice(NORMAL_DOMAINS)
    if idx % 12 == 0:
        domain = "finance.northstar.local"
    if idx % 17 == 0:
        domain = "support.microsoft.com"
    return {
        "timestamp": isoformat_utc(timestamp),
        "host": host,
        "src_ip": HOSTS[host]["ip"],
        "user": HOSTS[host]["user"],
        "query_name": f"{random.randint(100, 999)}.{domain}",
        "parent_domain": domain,
        "query_type": "A",
        "rcode_name": "NOERROR",
        "dest_ip": "10.20.0.5",
        "response_time_ms": random.randint(1, 80),
        "bytes_out": random.randint(56, 256),
        "rdata": "172.16.0.10",
        "source_port": 50000 + idx,
    }


def build_suspicious_query(host: str, timestamp: datetime, idx: int) -> dict:
    encoded = random.choice(SUSPICIOUS_SUBDOMAINS)
    label = f"{encoded}{idx % 17:02d}"
    query = f"{label}.{LAB_PARENT}"
    return {
        "timestamp": isoformat_utc(timestamp),
        "host": host,
        "src_ip": HOSTS[host]["ip"],
        "user": HOSTS[host]["user"],
        "query_name": query,
        "parent_domain": LAB_PARENT,
        "query_type": "A",
        "rcode_name": "NOERROR",
        "dest_ip": "10.20.0.5",
        "response_time_ms": random.randint(10, 220),
        "bytes_out": random.randint(150, 650),
        "rdata": "198.51.100.45",
        "source_port": 51000 + idx,
    }


def build_dataset() -> list[dict]:
    random.seed(42)
    events: list[dict] = []
    start = datetime(2026, 9, 30, 8, 0, tzinfo=timezone.utc)

    for host in HOSTS:
        for minute in range(180):
            ts = start + timedelta(minutes=minute)
            for idx in range(random.randint(7, 15)):
                events.append(build_normal_query(host, ts + timedelta(seconds=random.randint(0, 59)), idx))

    suspicious_start = start + timedelta(hours=1, minutes=6)
    for minute in range(20):
        ts = suspicious_start + timedelta(minutes=minute)
        for idx in range(random.randint(35, 70)):
            events.append(build_suspicious_query("FIN-WS-014", ts + timedelta(seconds=random.randint(0, 59)), idx + minute))

    normal_extra = [
        {
            "timestamp": isoformat_utc(start + timedelta(hours=1, minutes=5)),
            "host": "FIN-WS-014",
            "src_ip": HOSTS["FIN-WS-014"]["ip"],
            "user": HOSTS["FIN-WS-014"]["user"],
            "query_name": "display.office.com",
            "parent_domain": "office.com",
            "query_type": "A",
            "rcode_name": "NOERROR",
            "dest_ip": "10.20.0.5",
            "response_time_ms": 14,
            "bytes_out": 120,
            "rdata": "13.107.6.152",
            "source_port": 61000,
        }
    ]
    events.extend(normal_extra)
    return events


def main() -> None:
    root = repo_root()
    dataset = build_dataset()
    raw_path = root / "data" / "raw" / "dns_events.csv"
    write_csv(
        raw_path,
        [
            "timestamp",
            "host",
            "src_ip",
            "user",
            "query_name",
            "parent_domain",
            "query_type",
            "rcode_name",
            "dest_ip",
            "response_time_ms",
            "bytes_out",
            "rdata",
            "source_port",
        ],
        dataset,
    )

    df = pd.DataFrame(dataset)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    features = calculate_dns_features(df)
    features["host"] = features.get("host", "")
    features["risk_score"] = 0
    features["risk_level"] = "Low"
    processed_path = root / "data" / "processed" / "dns_features.csv"
    features.to_csv(processed_path, index=False)

    print(f"Generated {len(dataset)} DNS events -> {raw_path}")
    print(f"Generated feature dataset -> {processed_path}")


if __name__ == "__main__":
    main()
