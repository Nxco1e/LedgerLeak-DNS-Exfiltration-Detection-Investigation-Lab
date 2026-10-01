"""Generate synthetic Sysmon, Windows event, and network telemetry."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.utils import isoformat_utc, repo_root, write_csv, write_json

HOSTS = {
    "FIN-WS-014": {"ip": "10.20.14.37", "user": "npatel"},
    "FIN-WS-022": {"ip": "10.20.14.41", "user": "mchen"},
    "HR-WS-007": {"ip": "10.20.10.12", "user": "rlopez"},
    "IT-ADMIN-01": {"ip": "10.20.20.17", "user": "jreed"},
    "DC-01": {"ip": "10.20.0.10", "user": "svc_backup"},
}


def build_sysmon_events() -> list[dict]:
    base = datetime(2026, 9, 30, 8, 40, tzinfo=timezone.utc)
    records: list[dict] = []

    for host, details in HOSTS.items():
        for minute in range(70):
            timestamp = base + timedelta(minutes=minute)
            records.append(
                {
                    "EventID": 1,
                    "UtcTime": isoformat_utc(timestamp),
                    "ProcessGuid": f"{{{host.lower()}-guid-{minute}}}",
                    "ProcessId": 3000 + minute,
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c dir C:\\Finance\\Reports",
                    "CurrentDirectory": "C:\\Users\\{}\\Documents".format(details["user"]),
                    "User": f"NORTHSTAR\\{details['user']}",
                    "Computer": host,
                    "ParentImage": "C:\\Windows\\explorer.exe",
                    "ParentCommandLine": "explorer.exe",
                }
            )

    suspicious_tm = base + timedelta(hours=1, minutes=3)
    suspicious = [
        {
            "EventID": 1,
            "UtcTime": isoformat_utc(suspicious_tm + timedelta(minutes=0)),
            "ProcessGuid": "{fin-014-powershell-1}",
            "ProcessId": 8890,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand QwJvZ2luIFNwZWNr",
            "CurrentDirectory": "C:\\Users\\npatel\\Documents",
            "User": "NORTHSTAR\\npatel",
            "Computer": "FIN-WS-014",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
            "ParentCommandLine": "EXCEL.EXE /e \"Q3_Client_Reconciliation.xlsx\"",
        },
        {
            "EventID": 3,
            "UtcTime": isoformat_utc(suspicious_tm + timedelta(minutes=2)),
            "ProcessGuid": "{fin-014-powershell-1}",
            "ProcessId": 8890,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "User": "NORTHSTAR\\npatel",
            "Computer": "FIN-WS-014",
            "DestinationIp": "10.20.0.5",
            "DestinationPort": 53,
            "Protocol": "udp",
            "SourceIp": "10.20.14.37",
            "SourcePort": 56789,
        },
        {
            "EventID": 22,
            "UtcTime": isoformat_utc(suspicious_tm + timedelta(minutes=2)),
            "ProcessGuid": "{fin-014-powershell-1}",
            "ProcessId": 8890,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "User": "NORTHSTAR\\npatel",
            "Computer": "FIN-WS-014",
            "QueryName": "4d6f636b44617461.lab-sync.test",
            "QueryStatus": "SUCCESS",
            "DestinationHostname": "lab-sync.test",
            "DestinationIp": "198.51.100.45",
        },
    ]
    records.extend(suspicious)
    return records


def build_windows_events() -> list[dict]:
    base = datetime(2026, 9, 30, 8, 40, tzinfo=timezone.utc)
    rows = []
    for host, details in HOSTS.items():
        for minute in range(30):
            ts = base + timedelta(minutes=minute)
            rows.append(
                {
                    "timestamp": isoformat_utc(ts),
                    "host": host,
                    "event_id": 4624,
                    "user": details["user"],
                    "logon_type": "Interactive",
                    "logon_process": "User32",
                    "source_ip": "10.20.10.15",
                    "status": "SUCCESS",
                }
            )

    rows.append(
        {
            "timestamp": isoformat_utc(base + timedelta(hours=1, minutes=1)),
            "host": "FIN-WS-014",
            "event_id": 4624,
            "user": "npatel",
            "logon_type": "Interactive",
            "logon_process": "User32",
            "source_ip": "10.20.14.37",
            "status": "SUCCESS",
        }
    )
    return rows


def build_network_events() -> list[dict]:
    base = datetime(2026, 9, 30, 8, 40, tzinfo=timezone.utc)
    rows = []
    for host, details in HOSTS.items():
        for minute in range(40):
            ts = base + timedelta(minutes=minute)
            rows.append(
                {
                    "timestamp": isoformat_utc(ts),
                    "host": host,
                    "src_ip": details["ip"],
                    "dst_ip": "10.20.0.5",
                    "protocol": "udp",
                    "dest_port": 53,
                    "bytes_out": 128,
                    "bytes_in": 96,
                }
            )

    rows.append(
        {
            "timestamp": isoformat_utc(base + timedelta(hours=1, minutes=6)),
            "host": "FIN-WS-014",
            "src_ip": "10.20.14.37",
            "dst_ip": "198.51.100.45",
            "protocol": "udp",
            "dest_port": 53,
            "bytes_out": 512,
            "bytes_in": 128,
        }
    )
    return rows


def main() -> None:
    root = repo_root()
    sysmon_path = root / "data" / "raw" / "sysmon_events.json"
    windows_path = root / "data" / "raw" / "windows_events.csv"
    network_path = root / "data" / "raw" / "network_events.csv"

    write_json(sysmon_path, build_sysmon_events())
    write_csv(
        windows_path,
        ["timestamp", "host", "event_id", "user", "logon_type", "logon_process", "source_ip", "status"],
        build_windows_events(),
    )
    write_csv(
        network_path,
        ["timestamp", "host", "src_ip", "dst_ip", "protocol", "dest_port", "bytes_out", "bytes_in"],
        build_network_events(),
    )

    print(f"Generated {len(build_sysmon_events())} Sysmon events -> {sysmon_path}")
    print(f"Generated {len(build_windows_events())} Windows events -> {windows_path}")
    print(f"Generated {len(build_network_events())} network events -> {network_path}")


if __name__ == "__main__":
    main()
