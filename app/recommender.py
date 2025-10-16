import json
from typing import List
from utils.log_config import setup_logging
from data.store import InMemoryStore
from models.core_models import CoreIntent, DetectedThreat, MitigationAction

logger = setup_logging(__name__)

class Recommender:
    """
    This class is responsible for providing recommendations of mitigation actions for threats.
    It receives Threat (DetectedThreat) and find suitable MitigationAction based on threat type,
    attack type and priority.
    """

    def __init__(self):
        """
        Initialize the Recommender class.
        """
        self._store = InMemoryStore()

    def get_mitigations(self, threat: DetectedThreat) -> List[MitigationAction]:
        """
        Get a list of mitigation actions based on the detected threat.
        
        :param threat: DetectedThreat object
        :return: List of MitigationAction objects
        """
        mitigations = []
        for m in self._store.mitigation_get_all():
            if threat.threat_type == m.category \
                and threat.threat_name in m.threats:
                # Appends mitigation action if type and name of the threat match
                associations  = self._store.association_get(threat.uid)
                if not associations:
                    # If there are no associations, add the mitigation
                    mitigations.append(m)
                else:
                    # If there are associations, check if the mitigation is already associated
                    if m.uid not in [assoc.uid for assoc in associations]:
                        mitigations.append(m)
                    else:
                        logger.debug(f"Mitigation {m.uid} already associated with threat {threat.uid}")
        if not mitigations:
            logger.info(f"No mitigations found for threat: {threat.threat_name} of type: {threat.threat_type}")
            return None
        else :
            logger.debug(f"Found {len(mitigations)} mitigations for threat: {threat.threat_name} of type: {threat.threat_type}")
            # Order mitigations by priority (ascending)            
            mitigations.sort(key=lambda m: m.priority) 
            return mitigations
        

    def associate_mitigation(self, threat_uid: str, mitigation: MitigationAction) -> None:
        """
        Associate a mitigation action with an intent.
        :param threat_uid: UID of the threat
        :param mitigation_uid: UID of the mitigation action 
        """
        self._store.association_add(threat_uid, mitigation)


    def configure_mitigation(self, threat: DetectedThreat, mitigation: MitigationAction) -> MitigationAction:
        """
        Configure a mitigation action.
        
        :param mitigation: MitigationAction object
        """
        # TODO: Add wrapper to external LLM to configure the mitigation action
        if mitigation.category == MitigationAction.MitigationCategory.DETECTION:
            # configure detection mitigation action
            if mitigation.name == "firewall_pfcp_requests":
                request_type = threat.threat_name.split("_")[1].capitalize()
                mitigation.define_field("drop_percentage", "90%")
                mitigation.define_field("request_types", request_type)
            
            elif mitigation.name == "validate_smf_integrity":
                mitigation.define_field("check", "true")
                mitigation.define_field("action", "block")
            
            elif mitigation.name == "dns_rate_limiting":
                mitigation.define_field("rate", "9")
                mitigation.define_field("source_ip_filter", "0.0.0.0/0")
            
            elif mitigation.name == "ntp_access_control":
                host_list = ["dns-c1", "dns-c2", "dns-c3", "dns-c4", "dns-c5", "dns-c6", "dns-c7", "dns-c8", "dns-c9", "dns-c10"]
                mitigation.define_field("authorized_hosts", json.dumps(host_list))
                mitigation.define_field("mode", "whitelist")

        elif mitigation.category == MitigationAction.MitigationCategory.PREVENTION:
            if mitigation.name == "dns_rate_limiting":
                mitigation.define_field("rate", "9")
                mitigation.define_field("source_ip_filter", "0.0.0.0/0")
            
            elif mitigation.name == "rate_limiting":
                if threat.threat_name == "dns_amplification":
                    mitigation.define_field("device", "ceos3")
                    mitigation.define_field("interface", "eth2")
                elif threat.threat_name in ["ddos_download", "ddos_download_link"]:
                    mitigation.define_field("device", "ceos2")
                    mitigation.define_field("interface", "eth1")
                else:
                    mitigation.define_field("device", "ceos2")
                    mitigation.define_field("interface", "eth4")                
                mitigation.define_field("rate", "8")
            
            elif mitigation.name == "block_pod_address":
                mitigation.define_field("blocked_pod", "attacker")
                if threat.threat_name == "dns_amplification":
                    mitigation.define_field("device", "ceos3")
                    mitigation.define_field("interface", "eth1")
                elif threat.threat_name in ["ddos_download", "ddos_download_link"]:
                    mitigation.define_field("device", "ceos2")
                    mitigation.define_field("interface", "eth1")
                else:
                    mitigation.define_field("device", "ceos2")
                    mitigation.define_field("interface", "eth4")

        elif mitigation.category == MitigationAction.MitigationCategory.MITIGATION:
            # configure mitigation action
            if mitigation.name == "udp_traffic_filter":
                mitigation.define_field("protocol", "UDP")
                mitigation.define_field("source_ip_filter", threat.hosts[0])
                mitigation.define_field("destination_port", "123")  # Example port for NTP
            
            elif mitigation.name == "ntp_access_control":
                host_list = ["dns-c1", "dns-c2", "dns-c3", "dns-c4", "dns-c5", "dns-c6", "dns-c7", "dns-c8", "dns-c9", "dns-c10"]
                mitigation.define_field("authorized_hosts", json.dumps(host_list))
                mitigation.define_field("mode", "whitelist")
            
            elif mitigation.name == "block_ues_multidomain":
                str_hosts = "".join(threat.hosts).lower()
                if "upc" in str_hosts:
                    mitigation.define_field("domains", ["UPC"])
                    mitigation.define_field("rate_limiting", "10")
                elif "cnit" in str_hosts:
                    mitigation.define_field("domains", ["CNIT"])
                    mitigation.define_field("rate_limiting", "0")
                else:
                    mitigation.define_field("domains", ["ND"])
                    mitigation.define_field("rate_limiting", "0")
            
            elif mitigation.name == "define_dns_servers":
                mitigation.define_field("dns_servers", json.dumps(["dns-s"]))
            
            elif mitigation.name == "filter_malicious_access":
                mitigation.define_field("actor", "malicious")
                mitigation.define_field("response", "immediate")
            
            elif mitigation.name == "api_rate_limiting":
                mitigation.define_field("limit", "1000")
            
            elif mitigation.name == "dns_rate_limiting":
                mitigation.define_field("rate", "9")
                mitigation.define_field("source_ip_filter", "0.0.0.0/0")
            
            elif mitigation.name == "rate_limiting":
                mitigation.define_field("device", "ceos2")
                mitigation.define_field("interface", "eth4")
                mitigation.define_field("rate", "10")
            
            elif mitigation.name == "block_pod_address":
                mitigation.define_field("blocked_pod", "attacker")
                mitigation.define_field("device", "ceos2")
                mitigation.define_field("interface", "eth4")
        return mitigation

    def get_mitigation_host(self, intent: CoreIntent, mitigation: MitigationAction) -> str:
        """
        Get the mitigation host based on the threat and the mitigation action.
        """
        if mitigation.name == "udp_traffic_filter":
            if "node" in mitigation.parameters:
                result = mitigation.parameters.get("node", "ceos2")
            else:
                result = "ceos2"
        elif mitigation.name == "ntp_access_control":
            result = ""
        elif mitigation.name == "dns_rate_limiting":
            result = "ceos2"
        elif mitigation.name == "rate_limiting":
            result = mitigation.parameters.get("device", "ceos2")
        elif mitigation.name == "block_pod_address":
            result = "ceos2"
        elif mitigation.name == "block_ues_multidomain":
            result = "ceos3"
        elif mitigation.name == "define_dns_servers":
            result = "dns-c1"
        elif mitigation.name == "firewall_pfcp_requests":
            result = "ceos2"
        elif mitigation.name == "validate_smf_integrity":
            result = "5g-core"
        elif mitigation.name == "filter_malicious_access":
            result = "ceos2"
        elif mitigation.name == "api_rate_limiting":
            result = "ceos2"
        else:
            result = ""
        return result
