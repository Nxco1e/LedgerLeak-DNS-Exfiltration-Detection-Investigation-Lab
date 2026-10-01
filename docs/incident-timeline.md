# Incident Timeline

| Time (UTC) | Data Source | Host | User | Event | Analyst Interpretation |
| --- | --- | --- | --- | --- | --- |
| 08:41 | Windows Event Log | FIN-WS-014 | npatel | User authenticates to workstation | Normal business logon |
| 08:52 | Sysmon | FIN-WS-014 | npatel | Excel opens Q3_Client_Reconciliation.xlsx | Standard finance activity |
| 09:03 | Sysmon | FIN-WS-014 | npatel | Suspicious child process observed | Potential script or encoded execution sequence |
| 09:04 | Sysmon | FIN-WS-014 | npatel | PowerShell executes a benign lab command | Relevant process execution observed |
| 09:06 | DNS telemetry | FIN-WS-014 | npatel | First unusual DNS query to lab-sync.test | Evidence of abnormal DNS generation |
| 09:06-09:19 | DNS analytics | FIN-WS-014 | npatel | Repeated high-entropy labels and query spike | Strong indicator of tunneling or data transfer |
| 09:13 | Zeek | FIN-WS-014 | npatel | Structured DNS records identify repeated queries | Confirms network-level anomaly |
| 09:15 | Splunk | FIN-WS-014 | npatel | Detection triggers for volume, entropy, and query length | Operational alerting recognized |
| 09:23 | Correlation search | FIN-WS-014 | npatel | Endpoint plus DNS plus user context correlates | Incident assessment begins |
| 09:31 | Incident review | FIN-WS-014 | npatel | Suspected DNS tunneling or exfiltration behavior | Classified as a suspicious security event |

The timeline shows a clear sequence of process activity followed by abnormal DNS behavior and then validated SIEM detection.
