# Zeek Investigation

Zeek converts packet-level evidence into structured telemetry that is recognizable to security analysts and SIEM tools.

## Why Zeek matters

Zeek is useful here because it turns raw DNS queries into structured fields such as `query`, `qtype_name`, and `rcode_name`, enabling easier filtering and detection.

## Example fields

- `ts`: timestamp
- `uid`: unique connection ID
- `id.orig_h`: source IP
- `id.resp_h`: destination IP
- `query`: requested domain name
- `qtype_name`: record type
- `rcode_name`: DNS response code

## Sample ingestion

```bash
zeek -r data/pcap/ledgerleak_lab.pcap local

# then review generated logs in the current directory
ls *.log
```

## Sample Splunk import

```spl
index=zeek sourcetype=bro_dns | table _time, id.orig_h, query, qtype_name, rcode_name
```

This is the crucial bridge between raw network capture and SIEM review.
