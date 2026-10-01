# Detection Engineering Documentation

## Detection 1: Excessive DNS queries by endpoint

**Objective:** Detect sudden query spikes from a single workstation.

**Telemetry required:** DNS analytics, Splunk `dns_analytics` data.

**SPL query:**

```spl
index=dns_analytics | stats count by host, src_ip | where count > 200
```

**Threshold logic:** Query volume above expected baseline.

**Baseline logic:** Compare host activity over previous windows and use a z-score or percentile threshold.

**ATT&CK mapping:** T1071.004

**Expected false positives:** High-volume DNS from security tools or cloud apps.

**Tuning opportunities:** Add host baselines and domain filtering.

**Triage procedure:** Validate source host, user, and domain.

**Escalation criteria:** Query spike persists and is paired with long or encoded names.

## Detection 2: High-entropy DNS subdomain

**Objective:** Catch encoded or random-looking labels.

**Telemetry required:** `entropy`, `subdomain_length`, `query_name`.

**SPL query:**

```spl
index=dns_analytics entropy>3.4 | table _time host user query_name entropy
```

**Threshold logic:** Entropy above configured threshold.

**ATT&CK mapping:** T1048

This pattern is used as a supporting signal rather than a stand-alone malicious label.
