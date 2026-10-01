# LedgerLeak

DNS Exfiltration Detection & Investigation Lab

LedgerLeak is a detection-engineering and incident-response lab that investigates simulated DNS-based data exfiltration from a financial workstation by correlating endpoint, authentication, network, and SIEM telemetry.

## Overview

This project models a fictional financial operations environment where an employee on a Windows workstation begins generating abnormal DNS queries to a controlled lab domain. The investigation ties together:

- Windows endpoint telemetry from Sysmon and Event Logs
- Authentication activity from the domain controller
- Network evidence from PCAP, Zeek, and Splunk
- Python-based DNS feature extraction and anomaly scoring
- Splunk detections and correlation searches
- MITRE ATT&CK mapping and analyst triage documentation

The goal is to simulate one coherent incident story from raw packet capture to executive report without creating real malware or real exfiltration tooling.

## Incident Scenario

Northstar Financial Operations is a fictional company operating a finance environment with multiple user workstations. The primary affected host is FIN-WS-014, assigned to finance analyst npatel.

The timeline is:

- 08:41: User authenticates to FIN-WS-014
- 08:52: An Excel workbook is opened
- 09:03: A suspicious child process is observed
- 09:06: Unusual DNS activity begins against a synthetic lab domain, lab-sync.test
- 09:06-09:19: High-volume, high-entropy domain queries are generated from a single endpoint
- 09:15: Splunk detections begin to trigger
- 09:23: SOC analyst correlates the process, user, endpoint, and DNS evidence
- 09:31: The event is classified as suspected DNS tunneling / exfiltration in the simulated environment

## Architecture

```text
Windows Endpoint
    |
    | Sysmon + Windows Event Logs
    v
Splunk
    |
    +-------------------------------+
    |                               |
Endpoint Detection              Authentication Detection
    |                               |
    +---------------+---------------+
                    |
                    v
             Incident Timeline

Network Traffic
    |
    +---- PCAP ----> Wireshark
    |
    +---- Zeek ----> dns.log / conn.log
                         |
                         v
                       Splunk
                         |
                         v
               DNS Exfiltration Detection
                         |
                         v
                 Correlation Dashboard

Python Analytics
    |
    +---- DNS entropy calculation
    +---- subdomain length analysis
    +---- query frequency analysis
    +---- unique subdomain analysis
    +---- baseline deviation
                         |
                         v
                    Splunk CSV
                         |
                         v
                Risk Scoring Dashboard
```

## Technology Stack

- Splunk Enterprise / Splunk Free
- Wireshark for packet analysis
- Zeek for metadata extraction
- Sysmon for Windows endpoint telemetry
- Windows Event Logs
- Python 3.11+
- PowerShell for safe lab setup scripts only
- Sigma for portable detection rules
- SPL for SIEM detections
- MITRE ATT&CK mappings
- Git/GitHub
- JSON/CSV synthetic datasets
- PCAP evidence
- Markdown documentation

## Data Sources

This lab includes synthetic data across the following sources:

- `data/raw/dns_events.csv`
- `data/raw/sysmon_events.json`
- `data/raw/windows_events.csv`
- `data/raw/network_events.csv`
- `data/processed/dns_features.csv`
- `data/pcap/ledgerleak_lab.pcap`
- `zeek/sample_logs/dns.log`
- `zeek/sample_logs/conn.log`

## Detection Strategy

The project is designed around a realistic analyst workflow:

1. Establish endpoint and user context
2. Inspect DNS volume and query patterns
3. Analyze subdomain entropy and length
4. Correlate with suspicious Windows process creation
5. Compare against baseline deviation from normal behavior
6. Review authentication anomalies and timeline of related activity
7. Identify MITRE ATT&CK techniques supported by the telemetry
8. Produce a final incident assessment based on evidence

## Splunk Dashboard

The dashboard is named:

DNS Exfiltration Detection Center

It includes panels for:

- DNS queries over time
- top source endpoints
- top queried parent domains
- average query length by domain
- entropy distribution
- high-risk DNS events
- unique subdomains per parent domain
- suspicious processes
- risk score by endpoint
- incident timeline
- MITRE ATT&CK techniques
- analyst investigation table

## Wireshark Investigation

The packet capture is analyzed using Wireshark filters to isolate suspicious DNS activity, identify the source host, and compare malicious-looking query patterns against legitimate business traffic.

## Zeek Analysis

Zeek is used to generate structured DNS and connection metadata from packet capture for SIEM ingestion. This is the transition from raw network evidence into analyst-friendly telemetry.

## Endpoint Investigation

Sysmon and Windows Event Logs show process creation, PowerShell usage, and authentication behavior around the suspicious network activity. The analyst can correlate:

- user login context
- parent-child process relationships
- command line execution
- suspicious DNS generation
- network connections

## Risk Scoring

A rule-based risk engine combines multiple indicators such as:

- long subdomains
- high entropy
- high query rate
- large number of unique subdomains
- rare parent domains
- suspicious process correlation

The scoring is explainable and intentionally keeps a moderate threshold so the analyst can understand why an event is escalated.

## Baseline Detection

Each endpoint is given a baseline for:

- queries per minute
- unique domains per hour
- average query length
- average entropy
- NXDOMAIN percentage

The detection compares current activity against those baselines using z-score style deviation calculations.

## MITRE ATT&CK Mapping

Relevant ATT&CK mappings include:

- T1048: Exfiltration Over Alternative Protocol
- T1071: Application Layer Protocol
- T1059: Command and Scripting Interpreter
- T1059.001: PowerShell (when supported by evidence)

Additional mappings are included only where the synthetic telemetry supports them.

## Investigation Results

The lab demonstrates a realistic conclusion:

- FIN-WS-014 generated suspicious DNS traffic to lab-sync.test
- npatel was the active user
- powershell.exe or a similar approved utility executed suspicious-looking commands before abnormal DNS behavior
- the suspicious activity was statistically abnormal when compared to the host baseline
- the endpoint had supporting process and authentication context consistent with a malicious or suspicious workflow

## Repository Structure

```text
ledgerleak/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── config/
│   └── detection_thresholds.yaml
├── data/
│   ├── raw/
│   │   ├── dns_events.csv
│   │   ├── sysmon_events.json
│   │   ├── windows_events.csv
│   │   └── network_events.csv
│   ├── processed/
│   │   └── dns_features.csv
│   └── pcap/
│       └── ledgerleak_lab.pcap
├── src/
│   ├── generate_dns_data.py
│   ├── generate_endpoint_data.py
│   ├── dns_features.py
│   ├── entropy.py
│   ├── risk_engine.py
│   ├── baseline.py
│   └── utils.py
├── splunk/
│   ├── ingestion/
│   │   └── README.md
│   ├── searches/
│   │   ├── dns_volume.spl
│   │   ├── long_queries.spl
│   │   ├── entropy_detection.spl
│   │   ├── rare_domains.spl
│   │   ├── baseline_anomaly.spl
│   │   ├── process_dns_correlation.spl
│   │   └── combined_risk_detection.spl
│   └── dashboards/
│       └── dns_exfiltration_dashboard.xml
├── detections/
│   └── sigma/
│       ├── suspicious_dns_query_length.yml
│       ├── unusual_dns_volume.yml
│       └── suspicious_process_dns.yml
├── zeek/
│   ├── README.md
│   └── sample_logs/
│       ├── dns.log
│       └── conn.log
├── notebooks/
│   └── dns_anomaly_analysis.ipynb
├── docs/
│   ├── architecture.md
│   ├── lab-setup.md
│   ├── wireshark-investigation.md
│   ├── splunk-investigation.md
│   ├── zeek-investigation.md
│   ├── incident-timeline.md
│   ├── incident-report.md
│   ├── mitre-attack-mapping.md
│   ├── detection-engineering.md
│   ├── false-positive-analysis.md
│   └── interview-guide.md
└── screenshots/
    └── README.md
```

## How to Run

From the repository root:

```bash
cd ledgerleak
python -m pip install -r requirements.txt
python src/generate_dns_data.py
python src/generate_endpoint_data.py
pytest
```

## Splunk Setup

1. Create indexes named `endpoint`, `network`, `windows`, `zeek`, and `dns_analytics`.
2. Import CSV/JSON data into Splunk using the CSV input or JSON input settings.
3. Review the sample searches in `splunk/searches`.
4. Load dashboards from `splunk/dashboards/dns_exfiltration_dashboard.xml`.

## Screenshots

Capture screenshots for:

- Splunk overview dashboard
- high-risk DNS event drilldown
- endpoint process timeline
- Wireshark packet list
- Zeek DNS logs
- incident timeline
- MITRE mapping summary

## Key Findings

- A single financial workstation generated a large number of DNS queries to a lab-controlled domain.
- The queries were long, repetitive, and entropy-heavy.
- The suspicious traffic aligned temporally with PowerShell or script execution and a user login session.
- A network, endpoint, and authentication correlation showed the incident was not random background traffic.

## False Positives

This lab explicitly considers false positives such as CDNs, software updates, EDR telemetry, security products, and cloud service discovery. Long or highly encoded DNS strings are not automatically malicious unless combined with the right supporting context.

## Detection Engineering Lessons

This project is intentionally built around correlation and explainability rather than a single signature.

- one noisy indicator is insufficient
- combining endpoint, network, and identity signals reduces false positives
- baseline deviation helps separate background noise from suspicious behavior
- a risk score is easier for analysts to understand than a single boolean flag

## Future Improvements

- add real Zeek parsing and sample log normalization
- include a more advanced anomaly model with threat intelligence feeds
- automate Splunk app packaging
- add more potential endpoint telemetry for lateral movement and persistence context

## Disclaimer

This project is a fictional, synthetic cybersecurity lab created for educational, professional portfolio, and detection-engineering purposes only. It does not contain real malware, credential theft tooling, or harmful operational procedures.

---

This repository demonstrates a realistic SOC and DFIR workflow: from synthetic network evidence to endpoint investigation, forensic timeline reconstruction, and detection engineering.
