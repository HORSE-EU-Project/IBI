from typing import List
from constants import Const
from recommender import Recommender
from data.store import InMemoryStore
from models.api_models import DTEIntentType
from models.core_models import CoreIntent, DetectedThreat
from integrations.ckb import CKB
from integrations.cas import CASClient
from integrations.iandt import ImpactAnalysisDT
from integrations.siem import CustomSIEM
from integrations.rtr import RTR
from utils.log_config import setup_logging

logger = setup_logging("app.pipeline")

class IntentPipeline:

    def __init__(self):
        self._store = InMemoryStore()
        self.recommender = Recommender()
        self.rtr_client = RTR()
        self.cas_client = CASClient()
        self.ckb = CKB()
        self.iadt = ImpactAnalysisDT()
        self.customSIEM = CustomSIEM()


    def process_intents(self):

        # Expire threats according to their timeout
        self._store.expire_old_threats()

        # Get intents with status 'new'
        logger.debug("Starting intent pipeline iteration")
        ### List all valid intents
        intents = [i for i in self._store.intent_get_all() if not i.timedout()]
        threats = [t for t in self._store.threat_get_all()]
        
        # Loop over all threats to check whether they are expired
        # If they were under mitigation and expired, set them as MITIGATED
        self.update_expired_threats(threats)

        for intent in intents:
            logger.debug(f"Processing intent: {intent.get_uid()}")
            logger.debug(intent)
            # Check if there is a threat related to the intent
            if intent.intent_type == DTEIntentType.MITIGATION or intent.intent_type == DTEIntentType.DETECTION:
                # Checks detected threats (Mitigation or Detection)
                threats_mitigation = [t for t in threats if t.threat_type == DTEIntentType.MITIGATION or t.threat_type == DTEIntentType.DETECTION]
                self.process_mitigation_intents(intent, threats_mitigation)

            elif intent.intent_type == DTEIntentType.PREVENTION:
                threats_prevention = [t for t in threats if t.threat_type == DTEIntentType.PREVENTION]
                self.process_prevention_intents(intent, threats_prevention)
            else:
                logger.warning(f"Unknown intent type: {intent.intent_type} for intent: {intent.get_uid()}")
                continue

        self.iadt.process_queued_jobs()
        print("#" * 20)
        for job in self._store._dt_jobs:
            print(job)
        

    def update_expired_threats(self, threats):
        for t in threats:
            if t.get_status() == DetectedThreat.ThreatStatus.UNDER_MITIGATION and t.is_expired():
                logger.debug(f"Setting threat {t.uid} MITIGATED.")
                t.update_status(DetectedThreat.ThreatStatus.MITIGATED)
                # Generate a SIEM alarm for the expired threat
                self.customSIEM.send_log(t, CustomSIEM.AlarmType.MITIGATED)


    def process_mitigation_intents(self, intent, threats):
        """
        Process mitigation intents based on the detected threats.
        """
        logger.debug(f"Processing mitigation intent: {intent.get_uid()}")
        # Get mitigations for the intent


    def process_prevention_intents(self, intent, threats):
        """
        Process prevention intents based on the detected threats.
        """
        logger.debug(f"Processing prevention intent: {intent.get_uid()}")
        # Get mitigations for the intent
        # Checks forecasted threats (Prevention)
        for threat in threats:
            # if threat is NEW, propose a prevention
            if threat.get_status() == DetectedThreat.ThreatStatus.NEW:
                logger.debug(f"Processing threat {threat.uid} for intent: {intent.get_uid()}")
                # Query cKB
                self.ckb.query_ckb(threat.threat_name)
                available_actions = self.recommender.get_mitigations(threat)
                if not available_actions:
                    logger.warning(f"No mitigation found for threat: {threat.threat_name}")
                    continue
                # Parametrize the mitigation action
                available_actions[0] = self.recommender.configure_mitigation(threat, available_actions[0])
                # Associate the mitigation action with the threat
                self.recommender.associate_mitigation(threat.uid, available_actions[0])
                # Emulate in the IA-DT
                self.iadt.enqueue_simulation(threat, available_actions[0])
                threat.update_status(DetectedThreat.ThreatStatus.UNDER_EMULATION)


            if threat.get_status() == DetectedThreat.ThreatStatus.UNDER_EMULATION:
                # If threat is Under emulation/simulation on the DT
                # DT workflow is complete?
                    # Results are good?
                        # Send to RTR
                        # Set threat as UNDER_MITIGATION
                    # Results are bad
                        # Propose a new mitigation action
                        # Send to IA-NDT
                        # Set status to UNDER_EMULATION
                pass

            if threat.get_status() == DetectedThreat.ThreatStatus.REINCIDENT:
                # If threat is Reincident, propose a new mitigation action
                logger.debug(f"Detected REINCIDENT threat: {threat.uid} for intent: {intent.get_uid()}")
                pass

