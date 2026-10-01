# Wireshark Investigation

Wireshark helps the analyst inspect the PCAP and isolate the suspicious DNS data transfer pattern. The focus is to prove that the abnormal activity is both timed and scoped to the impacted endpoint.

## Core filters

- `dns`
- `dns.qry.name`
- `ip.addr == 10.20.14.37`
- `dns && ip.src == 10.20.14.37`
- `dns.flags.response == 0`
- `dns.qry.name contains "lab-sync.test"`

## Investigation workflow

1. Filter to DNS traffic.
2. Limit to the suspect source IP, `10.20.14.37`.
3. Inspect the query names and timestamps.
4. Compare repeated queries against normal browsing and office traffic.
5. Use Conversations and Endpoints to see the total volume and scope.
6. Follow UDP stream where useful to confirm the transport pattern.
7. Export relevant packets as evidence.

## What analysts should observe

| Observation | Meaning |
| --- | --- |
| Repeated queries from FIN-WS-014 | Endpoint is the likely source of suspicious behavior |
| `lab-sync.test` in the query name | Controlled lab domain receiving encoded-looking requests |
| Long and high-entropy labels | Suggests encoded or algorithmically-generated strings |
| Sparse normal traffic outside the anomaly window | Supports a timeline-based interpretation |
| DNS activity near PowerShell process creation | Improves confidence in the incident correlation |

## Analyst procedure

- Start with `dns && ip.addr == 10.20.14.37`
- Focus on `dns.qry.name` field to identify repeated labels
- Check if query length is abnormal relative to normal domains
- Compare with office traffic, SaaS domains, and Microsoft services
- Use statistics to confirm the anomaly is not a single outlier

This process shows how packet evidence transitions into SIEM-ready indicators.
