# Splunk Investigation

Splunk is the central workflow layer for this lab. It connects endpoint, authentication, and DNS evidence in one place.

## Data model

Use these indexes:

- `endpoint`
- `network`
- `windows`
- `zeek`
- `dns_analytics`

## Import workflow

1. Import `data/raw/dns_events.csv` into `dns_analytics`.
2. Import `data/raw/network_events.csv` into `network`.
3. Import `data/raw/windows_events.csv` into `windows`.
4. Import `data/raw/sysmon_events.json` into `endpoint`.
5. Import processed analytics from `data/processed/dns_features.csv` into `dns_analytics` if needed.

## Initial searches

```spl
index=dns_analytics | stats count by host, parent_domain
index=endpoint EventID=1 | stats count by Computer, Image, User
index=windows event_id=4624 | stats count by host, user
```

## Investigation mindset

The SOC analyst should begin by identifying the abnormal host, then correlate that host with the expected user activity and suspicious process execution. Only after that should the analyst examine the DNS data and risk score.
