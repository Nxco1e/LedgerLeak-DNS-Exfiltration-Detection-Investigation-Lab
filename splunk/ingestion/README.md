# Splunk Ingestion Guide

Import the generated CSV/JSON artifacts into the respective indexes.

## Recommended indexes

- endpoint
- network
- windows
- zeek
- dns_analytics

## Example import steps

1. Open Splunk and navigate to Settings > Data Inputs.
2. Add a CSV input for `data/raw/dns_events.csv`.
3. Add a CSV input for `data/raw/windows_events.csv`.
4. Add a CSV input for `data/raw/network_events.csv`.
5. Add a JSON input for `data/raw/sysmon_events.json`.
6. Assign each source to the relevant index.

This project is designed to mimic a realistic SIEM workflow rather than a simple lab demo.
