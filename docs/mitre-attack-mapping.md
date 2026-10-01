# MITRE ATT&CK Mapping

This synthetic lab supports only the ATT&CK mappings that are directly backed by the generated telemetry.

| Technique | Technique ID | Observed Evidence | Source | Confidence | Reasoning |
| --- | --- | --- | --- | --- | --- |
| Application Layer Protocol: DNS | T1071.004 | Repeated DNS queries to lab-sync.test | Zeek/Splunk | High | The suspicious workflow uses DNS as an application-layer data channel. |
| Exfiltration Over Alternative Protocol | T1048 | High-volume, encoded DNS labels to a controlled lab domain | DNS analytics | High | The behavior is consistent with data transfer over DNS in a controlled lab. |
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell process creation near the anomaly window | Sysmon | Medium | PowerShell is the strongest process correlate available. |

## Notes

The lab intentionally avoids forcing ATT&CK mappings where the evidence is weak. Correlation strengthens the conclusion rather than direct labels.
