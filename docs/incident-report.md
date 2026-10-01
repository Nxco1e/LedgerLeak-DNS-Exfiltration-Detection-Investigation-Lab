# Incident Report

## Executive Summary

A simulated phishing-like data workflow or suspicious automation process executed on FIN-WS-014 caused a burst of unusual DNS traffic to a controlled lab domain. The event was investigated using endpoint telemetry, authentication records, network evidence, and Splunk correlation.

## Incident Classification

Suspected DNS tunneling / data exfiltration over DNS.

## Affected Asset

- Host: FIN-WS-014
- IP: 10.20.14.37
- User: npatel

## Detection Method

The investigation combined:

- DNS query volume anomalies
- unusually long query names
- elevated entropy scores
- process creation correlation
- baseline deviation relative to normal host behavior

## Timeline

See the incident timeline in `docs/incident-timeline.md`.

## Technical Analysis

Analysis shows a short sequence of business-normal activity followed by a suspicious PowerShell execution and then a DNS spike. The suspicious activity occurred in the same window as the analyst's expected work activity but with an abnormal query pattern.

## Network Evidence

A GIS-style DNS review showed repeated DNS queries to `lab-sync.test` with long encoded-looking labels. The query pattern is not consistent with normal office traffic or application queries.

## Endpoint Evidence

Sysmon records show a parent-child process lineage involving Excel and PowerShell. The process behavior is consistent with script or command-based execution in the same time window as the DNS anomaly.

## SIEM Evidence

Splunk detections showed a spike in query volume with high entropy and long subdomains. Combined with baseline comparison, the alerting logic elevated confidence in the incident assessment.

## MITRE ATT&CK Mapping

- T1071.004: Application Layer Protocol: DNS
- T1048: Exfiltration Over Alternative Protocol
- T1059.001: PowerShell

## Indicators

- `lab-sync.test`
- `10.20.14.37`
- `powershell.exe`
- `FIN-WS-014`
- suspicious query pattern with high entropy and long labels

## False Positive Considerations

The detection should be treated as suspicious but not conclusive until correlated with process and user evidence. Some security tooling and edge services can resemble tunnelled DNS, but the combined evidence remains supportive.

## Containment Recommendations

- isolate FIN-WS-014 from the network
- review recent file systems and cloud sync activity
- verify whether the suspicious process was user-triggered or malicious
- preserve the PCAP and host logs for forensic review

## Detection Improvements

- add stronger endpoint baselines
- refine entropy thresholds for the environment
- compare against known SaaS service names and CDNs
- tune risk scoring using historical data

## Lessons Learned

The strongest evidence in this lab comes from correlation. Isolated indicators are useful, but endpoint plus network plus identity evidence is what makes the investigation credible.

## Conclusion

The synthetic lab demonstrates the kind of investigation a junior or mid-level SOC analyst could perform in production: gather evidence, correlate the host, validate the user context, and classify the case based on pattern, behavior, and supporting telemetry.
