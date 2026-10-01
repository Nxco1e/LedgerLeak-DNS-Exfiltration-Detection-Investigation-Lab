# Lab Setup

This lab is designed for a safe, synthetic investigation environment.

## Prerequisites

- Python 3.11+
- Splunk Enterprise or Splunk Free
- Wireshark
- Zeek (for sample metadata generation)
- Sysmon (synthetic sample logs only)
- Git

## Steps

1. Clone the repository.
2. Create a virtual environment.
3. Install requirements.
4. Generate synthetic datasets.
5. Import CSV and JSON data into Splunk.
6. Review detections in `splunk/searches`.
7. Open the PCAP in Wireshark.
8. Inspect the Zeek logs and correlate them with endpoint logs.

## Commands

```bash
cd ledgerleak
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
python -m pip install -r requirements.txt
python src/generate_dns_data.py
python src/generate_endpoint_data.py
pytest
```

The generated information is synthetic and designed for analyst training and portfolio demonstration only.
