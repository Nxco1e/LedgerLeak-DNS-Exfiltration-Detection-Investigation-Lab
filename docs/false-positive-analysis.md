# False Positive Analysis

A DNS detection strategy based only on long query names is weak. Many benign systems create long or unusual DNS names.

## Legitimate systems that may look suspicious

- CDNs and edge services
- EDR and security products
- software update checks
- cloud app metadata or service discovery
- analytics and tracking frameworks
- SaaS applications with global DNS traffic

## Why long query does not equal attack

A long query alone may be harmless. The correct approach is to combine signals.

- Long DNS query alone: low confidence
- Long query + high entropy: medium confidence
- Long query + high entropy + high volume: high confidence
- Long query + high entropy + high volume + suspicious process: very high confidence

## Why correlation matters

The incident story in LedgerLeak is strong because it combines:

- endpoint-based process anomalies
- user login context
- DNS volume spike
- unusual domain usage
- abnormal entropy and label structure

This reduces the risk of false positives while keeping the detections explainable.
