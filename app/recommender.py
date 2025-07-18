from constants import Const
from utils.log_config import setup_logging
from data.mitigations import MITIGATION_DATA

logger = setup_logging(__file__)

class Recommender:

    def __init__(self):
        pass

    def get_mitigation(self, intent_type, threat):

        #TODO: Call the CKB service to get mitigation actions here

        """
        Get mitigation actions based on intent type and threat.
        """
        return MITIGATION_DATA.get(intent_type, {}).get(threat, [])
    

        