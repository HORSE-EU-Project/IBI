from constants import Const
from typing import List
from utils.log_config import setup_logging
from data.store import InMemoryStore
from models.core_models import DetectedThreat, MitigationAction

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
                # Appens mitigation action if type and name of the threat match
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
        if mitigation.category == MitigationAction.MitigationCategory.DETECTION:
            # configure detection mitigation action
            pass
        elif mitigation.category == MitigationAction.MitigationCategory.PREVENTION:
            # configure prevention mitigation action
            pass
        elif mitigation.category == MitigationAction.MitigationCategory.MITIGATION:
            # configure mitigation action
            if mitigation.name == "udp_traffic_filter":
                mitigation.define_field("protocol", "UDP")
                mitigation.define_field("source_ip_filter", threat.hosts[0])
                mitigation.define_field("destination_port", "123")  # Example port for NTP
            
            # TODO: parametrize other mitigation actions here
        return mitigation

    def get_mitigation_host(self, threat: DetectedThreat, mitigation: MitigationAction) -> str:
        # TODO: implement this method with the values according to the mitigation action
        """
        Get the mitigation host based on the threat and the mitigation action.
        """
        if mitigation.name == "udp_traffic_filter":
            return "ceos2"
        else:
            return ""