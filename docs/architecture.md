# Architecture Overview

The LedgerLeak lab is built to show one coherent incident story across multiple telemetry sources. Each component contributes a different layer of evidence to the same investigation.

## Core design

### Endpoint telemetry
- Sysmon captures process creation, command lines, parent-child relationships, and network events.
- This is the best source to answer: which process launched the suspicious workflow?

### Authentication telemetry
- Windows Event Logs provide logon evidence and user context.
- This answers: which user was active on the host during the suspicious behavior?

### Network telemetry
- PCAP and Zeek convert raw DNS traffic into structured evidence.
- This answers: which domain was contacted, how often, and from which endpoint?

### SIEM analysis
- Splunk correlates the endpoint and network data into a single analyst view.
- This answers: did the process anomaly precede the DNS anomaly and did the risk score escalate?

### Python analytics
- Feature extraction calculates entropy, query frequency, unique subdomains, and query length.
- This supports a detection engineering workflow rather than a one-off signature.

## Why the incident is realistic

The design avoids a single isolated detection. Instead, the investigation requires correlation across:

- host identity
- user session
- parent process
- DNS query count
- domain reputation/rarity
- baseline deviation
- timing and sequencing

That makes the project portfolio-quality because it looks like a real SOC workflow.
