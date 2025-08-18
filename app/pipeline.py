from constants import Const
from recommender import Recommender
from data.store import InMemoryStore
from models.api_models import DTEIntentType
from integrations.external import CKB, CASClient, RTR, ImpactAnalysisDT, ExternalSyslog
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
        self.external_syslog = ExternalSyslog()

    def process_intents(self):

        # Expire threats according to their timeout
        self._store.expire_old_threats()

        # Get intents with status 'new'
        logger.info("Starting intent pipeline iteration")
        ### List all valid intents
        intents = [i for i in self._store.intent_get_all() if not i.timedout()]
        threats = [t for t in self._store.threat_get_all() if not t.is_expired()]

        for intent in intents:
            logger.debug(f"Processing intent: {intent.get_uid()}")
            logger.debug(intent)
            # Check if there is a threat related to the intent
            if intent.intent_type == DTEIntentType.MITIGATION or intent.intent_type == DTEIntentType.DETECTION:
                # Checks detected threats (Mitigation or Detection)
                pass
            elif intent.intent_type == DTEIntentType.PREVENTION:
                # Checks forecasted threats (Prevention)
                for threat in threats:
                    # if threat is NEW, propose a prevention
                    if threat.get_status() == threat.ThreatStatus.NEW:
                        logger.debug(f"Detected NEW threat: {threat.uid} for intent: {intent.get_uid()}")
                        # Query cKB
                        self.ckb.query_ckb(threat.threat_name)
                        available_actions = self.recommender.get_mitigations(threat)
                        if not available_actions:
                            logger.warning(f"No mitigation found for threat: {threat.threat_name}")
                            continue
                        # Emulate in the IA-DT
                        self.iadt.emulate(threat, available_actions[0])

                    # if threat is REINCIDENT try a different migigation

            else:
                logger.warning(f"Unknown intent type: {intent.intent_type} for intent: {intent.get_uid()}")
                continue
                                
        return
        try:
            logger.info("Checking new intents")
            intents = self.intent_manager.get_all(status=Const.INTENT_STATUS_NEW)
            for intent in intents:
                # Processing mitigation intents
                if intent.get("intent_type") == DTEIntentType.MITIGATION:
                    logger.info(f"Processing intent ID: {intent.get('id')}, TYPE: {intent.get('intent_type')}")
                    # Set status of intent to "processing"
                    # Query cKB
                    self.ckb.query_ckb(intent.get("threat"))

                    # Get mitigation actions from recommender
                    mitigations = self.recommender.get_mitigation(intent)

                    if not mitigations:
                        logger.warning(f"No mitigation found for intent ID: {intent.get('id')}")
                        continue

                    # Validate with CAS
                    final_mitigation = self.cas_client.process_mitigation(intent, mitigations)

                    # Store associate mitigation to intent
                    self.recommender.associate_mitigation(
                        intent.get("id"), 
                        final_mitigation  # Assuming we take the first mitigation action
                    )

                    # Send to RTR
                    rtr_workflow = self.rtr_client.create_workflow(
                        intent.get("id"), 
                        final_mitigation
                    )
                    self.rtr_client.send_workflow(rtr_workflow)

                    # Set status of intent to "under mitigation"
                    self.intent_manager.update_status(
                        intent.get("id"), 
                        Const.INTENT_STATUS_UNDER_MITIGATION
                    )
                
                # Processing prevention intents
                if intent.get("intent_type") == DTEIntentType.PREVENTION:
                    logger.info(f"Processing intent ID: {intent.get('id')}, TYPE: {intent.get('intent_type')}")
                    # Set status of intent to "processing"
                    # Query cKB
                    ckb = CKB()
                    ckb.query_ckb(intent.get("threat"))

                    # Get prevention actions from recommender

                    # Send to IA-Digital Twin
                    iadt = ImpactAnalysisDT()
                    iadt.send_to_iadt(intent.get("id"))
                    self.intent_manager.update_status(
                        intent.get("id"), 
                        Const.INTENT_STATUS_NDT_SENT
                    )

                    # Validate with CAS

                    # Send to RTR

                    # Set status of intent to "under mitigation"
                    # self.intent_manager.update_status(
                    #     intent.get("id"), 
                    #     Const.INTENT_STATUS_UNDER_MITIGATION
                    # )

            
        except Exception as e:
            logger.error(f"Error querying Elasticsearch: {e}")
        
        # Set intents "under mitigation" that reached timeout to "mitigated"