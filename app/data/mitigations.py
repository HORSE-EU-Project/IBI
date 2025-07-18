MITIGATION_DATA = {
    "mitigation": {
        "hello_world": [
            {
                "attack_name": "hello_world",
                "mitigation_name": "execute_test_1",
                "intent_id": "10001",
                "fields": {
                    "test_id": "1",
                    "modules": ["Pre-processing", "DEME", "DTE", "IBI", "CKB", "RTR", "ePEM", "CAS"]
                }
            }
        ],
        "ntp_ddos": [
            {
                "attack_name": "ddos_amplification",
                "mitigation_name": "udp_traffic_filter",
                "intent_id": "20001",
                "fields": {
                    "protocol": "UDP",
                    "source_ip_filter": ["malicious_ips"],
                    "destination_port": "123"
                }
            },
            {
                "attack_name": "ddos_amplification",
                "mitigation_name": "ntp_access_control",
                "intent_id": "20002",
                "fields": {
                    "authorized_hosts": ["whitelisted_ips"],
                    "mode": "whitelist"
                }
            }
        ],
        "dns_ddos": [
            {
                "attack_name": "multidomain",
                "mitigation_name": "block_ues_multidomain",
                "intent_id": "60001",
                "fields": {
                    "domains": ["UPC", "CNIT"],
                    "rate_limiting": "generic"
                }
            },
            {
                "attack_name": "multidomain",
                "mitigation_name": "define_dns_servers",
                "intent_id": "60002",
                "fields": {
                    "dns_servers": ["server_list"]
                }
            },
            {
                "attack_name": "?",
                "mitigation_name": "dns_rate_limiting",
                "intent_id": "30001",
                "fields": {
                    "rate": "20",
                    "source_ip_filter": ["malicious_ips"]
                }
            },
            {
                "attack_name": "",
                "mitigation_name": "rate_limiting",
                "intent_id": "30002",
                "fields": {
                    "device": "router2",
                    "interface": "eth1",
                    "rate": "10mbps"
                }
            },
            {
                "attack_name": "",
                "mitigation_name": "block_pod_address",
                "intent_id": "30003",
                "fields": {
                    "blocked_pod": "ue1",
                    "device": "router2",
                    "interface": "eth1"
                }
            }
        ],
        "nef": [
            {
                "attack_name": "nf_exposure",
                "mitigation_name": "filter_malicious_access",
                "intent_id": "80001",
                "fields": {
                    "actor": "malicious",
                    "response": "immediate"
                }
            },
            {
                "attack_name": "nf_exposure",
                "mitigation_name": "api_rate_limiting",
                "intent_id": "80002",
                "fields": {
                    "limit": "X requests per minute"
                }
            }
        ]
    },
    "prevention": {
        "hello_world": [
            {
                "attack_name": "",
                "mitigation_name": "execute_test_2",
                "intent_id": "10002",
                "fields": {
                    "test_id": "2",
                    "modules": ["Pre-processing", "EM", "P&P DT", "DTE", "IBI", "CKB", "IA DT", "RTR", "ePEM", "CAS"]
                }
            }
        ],
        "dns_ddos": [
            {
                "attack_name": "dns_amplification",
                "mitigation_name": "dns_rate_limiting",
                "intent_id": "30001",
                "fields": {
                    "rate": "20",
                    "source_ip_filter": ["malicious_ips"]
                }
            },
            {
                "attack_name": "",
                "mitigation_name": "rate_limiting",
                "intent_id": "30002",
                "fields": {
                    "device": "router2",
                    "interface": "eth1",
                    "rate": "10mbps"
                }
            },
            {
                "attack_name": "",
                "mitigation_name": "block_pod_address",
                "intent_id": "30003",
                "fields": {
                    "blocked_pod": "ue1",
                    "device": "router2",
                    "interface": "eth1"
                }
            }
        ],
        "download_ddos": [
            {
                "attack_name": "",
                "mitigation_name": "block_pod_address",
                "intent_id": "40002",
                "fields": {
                    "blocked_pod": "attacker",
                    "device": "router2",
                    "interface": "eth1"
                }
            }
        ],
        "donwload_ddos": [
            {
                "attack_name": "ddos_download_link",
                "mitigation_name": "rate_limiting",
                "intent_id": "40001",
                "fields": {
                    "device": "router2",
                    "interface": "eth1",
                    "rate": "10mbps"
                }
            }
        ]
    },
    "detection": {
        "pfcp": [
            {
                "attack_name": "signaling_pfcp",
                "mitigation_name": "firewall_pfcp_requests",
                "intent_id": "90001",
                "fields": {
                    "drop_percentage": "X%",
                    "request_types": ["Deletion", "Establishment", "Modification"]
                }
            },
            {
                "attack_name": "",
                "mitigation_name": "validate_smf_integrity",
                "intent_id": "90002",
                "fields": {
                    "check": "if compromised",
                    "action": "restart"
                }
            }
        ]
    }
}