import pandas as pd

from src.dns_features import calculate_dns_features


def test_dns_features_include_expected_columns():
    data = pd.DataFrame(
        [
            {
                "timestamp": "2026-09-30T09:06:00Z",
                "host": "FIN-WS-014",
                "src_ip": "10.20.14.37",
                "user": "npatel",
                "query_name": "4d6f636b44617461.lab-sync.test",
                "parent_domain": "lab-sync.test",
            },
            {
                "timestamp": "2026-09-30T09:06:01Z",
                "host": "FIN-WS-014",
                "src_ip": "10.20.14.37",
                "user": "npatel",
                "query_name": "microsoft.com",
                "parent_domain": "microsoft.com",
            },
        ]
    )
    features = calculate_dns_features(data)
    assert "full_domain_length" in features.columns
    assert "subdomain_length" in features.columns
    assert "entropy" in features.columns
    assert features["parent_domain"].eq("lab-sync.test").any()
