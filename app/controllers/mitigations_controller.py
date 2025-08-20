from data.store import InMemoryStore
from models.core_models import MitigationAction

from utils.log_config import setup_logging

logger = setup_logging(__name__)

class MitigationsController:

    """
    Static Method to populate the In Memory database with the mitigation actions
    """
    @staticmethod
    def populate_mitigation_actions():
        store = InMemoryStore()
        # Sample mitigation actions

        mitigations = [
            # Demo 0
            MitigationAction(name="execute_test_1", category="mitigation", threats=["hello_world"], fields=["test_id", "modules"]),
            MitigationAction(name="execute_test_2", category="prevention", threats=["hello_world"], fields=["test_id", "modules"]),
            # Demo 1
            MitigationAction(name="udp_traffic_filter", category="mitigation", threats=["ddos_amplification"], fields=["protocol", "source_ip_filter", "destination_port"]),
            MitigationAction(name="ntp_access_control", category="mitigation", threats=["ddos_amplification"], fields=["authorized_hosts", "mode"]),
            # Demo 2
            MitigationAction(name="dns_rate_limiting", category="prevention", threats=["dns_amplification"], fields=["rate", "source_ip_filter"]),
            MitigationAction(name="rate_limiting", category="prevention", threats=["dns_amplification"], fields=["device", "interface", "rate"]),
            MitigationAction(name="block_pod_address", category="prevention", threats=["dns_amplification"], fields=["blocked_pod", "device", "interface"]),
            # Demo 3
            MitigationAction(name="rate_limiting", category="prevention", threats=["ddos_download_link"], fields=["device", "interface", "rate"]),
            MitigationAction(name="block_pod_address", category="prevention", threats=["ddos_download_link"], fields=["blocked_pod", "device", "interface"]),
            # Demo 4
            # MitigationAction(name="data_reset_request", category="ND", threats=["data_poisoning"], fields=["target_module", "reset_interval"]),
            # MitigationAction(name="data_verification_request", category="ND", threats=["data_poisoning"], fields=["target_module", "verification_mode"]),
            # Demo 5
            MitigationAction(name="block_ues_multidomain", category="mitigation", threats=["multidomain"], fields=["domains", "rate_limiting"]),
            MitigationAction(name="define_dns_servers", category="mitigation", threats=["multidomain"], fields=["dns_servers"]),
            # Demo 6
            MitigationAction(name="firewall_pfcp_requests", category="detection", threats=["signaling_pfcp"], fields=["drop_percentage", "request_types"]),
            MitigationAction(name="validate_smf_integrity", category="detection", threats=["signaling_pfcp"], fields=["check", "action"]),
            MitigationAction(name="filter_malicious_access", category="mitigation", threats=["nf_exposure"], fields=["actor", "response"]),
            MitigationAction(name="api_rate_limiting", category="mitigation", threats=["nf_exposure"], fields=["limit"]),
            MitigationAction(name="firewall_pfcp_requests", category="detection", threats=["signaling_pfcp"], fields=["drop_percentage", "request_types"]),
            MitigationAction(name="validate_smf_integrity", category="detection", threats=["signaling_pfcp"], fields=["check", "action"]),
            MitigationAction(name="dns_rate_limiting", category="mitigation", threats=["poisoning_and_amplification"], fields=["rate", "source_ip_filter"]),
            MitigationAction(name="rate_limiting", category="mitigation", threats=["poisoning_and_amplification"], fields=["device", "interface", "rate"]),
            MitigationAction(name="block_pod_address", category="mitigation", threats=["poisoning_and_amplification"], fields=["blocked_pod", "device", "interface"])
        ]
        
        # Store all mitigation actions
        for mitigation in mitigations:
            store.mitigation_add(mitigation)
        
        logger.info(f"Populated {len(mitigations)} mitigation actions")

    @staticmethod
    def dump_mitigation_actions():
        """
        Dump all mitigation actions to the logger
        """
        store = InMemoryStore()
        mitigations = store.mitigation_get_all()
        logger.debug("Dumping Mitigation Actions:")
        for mitigation in mitigations:
            logger.debug(mitigation.to_dict())