from concurrent.futures import thread
from recommender import Recommender
from data.store import InMemoryStore
from models.api_models import DTEIntentType
from models.core_models import CoreIntent, DTJob, DetectedThreat
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

        if self._store._ibi_compromised:
            logger.warning("######################################################################")
            logger.warning("#  The component should be manually restarted.                       #")
            logger.warning("#  The IBI component cannot proceed because it might be compromised. #")
            logger.warning("######################################################################")
            return

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

        # Process IA-NDT jobs
        self.iadt.process_queued_jobs()
        # Check if intent is satisfied
        self.check_intent_fulfillment(intents, threats)
        return
        

    def check_intent_fulfillment(self, intents, threats):
        """
        Check if each CoreIntent is fulfilled by examining threats.
        An intent is NOT satisfied if there are any threats with status in 
        [NEW, UNDER_EMULATION, UNDER_MITIGATION, REINCIDENT] with corresponding 
        threat_type and threat_name as the intent_type and threat.
        """
        logger.debug("Checking intent fulfillment...")
        
        for intent in intents:
            logger.debug(f"Checking fulfillment for intent: {intent.get_uid()}")
            
            # Find threats that match this intent's type and threat name
            matching_threats = [
                threat for threat in threats 
                if (threat.threat_type == intent.intent_type and 
                    threat.threat_name == intent.threat)
            ]
            
            # Check if any matching threats have unsatisfied statuses
            unsatisfied_threats = [
                threat for threat in matching_threats
                if threat.get_status() in [
                    DetectedThreat.ThreatStatus.NEW,
                    DetectedThreat.ThreatStatus.UNDER_EMULATION,
                    DetectedThreat.ThreatStatus.UNDER_MITIGATION,
                    DetectedThreat.ThreatStatus.REINCIDENT
                ]
            ]
            
            # Intent is satisfied if there are no unsatisfied threats
            if len(unsatisfied_threats) == 0:
                intent.set_fulfilled(True)
                logger.debug(f"Intent {intent.get_uid()} is SATISFIED")
            else:
                intent.set_fulfilled(False)
                logger.debug(f"Intent {intent.get_uid()} is NOT SATISFIED - found {len(unsatisfied_threats)} unsatisfied threats")
        return


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
        for threat in threats:
            if threat.get_status() == DetectedThreat.ThreatStatus.NEW:
                logger.debug(f"Processing threat: {threat.uid} (Status: NEW)")
                # Query cKB
                self.ckb.query_ckb(threat.threat_name)
                available_actions = self.recommender.get_mitigations(threat)
                if not available_actions:
                    logger.warning(f"No mitigation found for threat: {threat.threat_name}")
                    continue
                # Parametrize the mitigation action
                mitigation_action = self.recommender.configure_mitigation(threat, available_actions[0])
                # Associate the mitigation action with the threat
                self.recommender.associate_mitigation(threat.uid, mitigation_action)
                # Test the mitigation action with CAS
                # Test with CAS
                cas_result = self.cas_client.validate(intent, mitigation_action)
                        
                while cas_result == self.cas_client.PARTIAL:
                    mitigation_action = self.cas_client.tune_mitigation(mitigation_action)
                    self._store.association_update(threat.uid, mitigation_action)
                    cas_result = self.cas_client.validate(intent, mitigation_action)

                if cas_result == self.cas_client.INVALID:
                    logger.debug(f"Mitigation {mitigation_action.uid} was rejected by CAS. Setting as NEW for new cycle.")
                    threat.update_status(DetectedThreat.ThreatStatus.NEW)
                
                if cas_result == self.cas_client.VALID:
                    logger.debug(f"Mitigation {mitigation_action.uid} was accepted by CAS. Sending to RTR and setting UNDER_MITIGATION.")
                    self.rtr_client.enforce_mitigation(intent, mitigation_action)
                    threat.update_status(DetectedThreat.ThreatStatus.UNDER_MITIGATION)

            if threat.get_status() == DetectedThreat.ThreatStatus.REINCIDENT:
                # If threat is Under mitigation, propose a new mitigation action
                logger.debug(f"Processing threat: {threat.uid} (Status: REINCIDENT). Setting as NEW for new cycle.")
                threat.update_status(DetectedThreat.ThreatStatus.NEW)
                pass


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
                logger.debug(f"Processing threat: {threat.uid} (Status: NEW)")
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
                logger.debug(f"Processing threat: {threat.uid} (Status: UNDER EMULATION)")
                
                # If threat is Under emulation/simulation on the DT
                dt_job = self._store.dt_job_get_by_threat(threat.uid)
                # DT workflow is complete?
                if dt_job and dt_job.status == DTJob.JobStatus.COMPLETED:
                    # Results are good?
                    if self.iadt.check_results(threat.uid, dt_job.kpi_before, dt_job.kpi_after):
                        # Recover the mitigation action linked to the thread
                        mitigation_actions = self._store.association_get(threat.uid)
                        mitigation_action = mitigation_actions[-1] if mitigation_actions else None
                        # Test with CAS
                        cas_result = self.cas_client.validate(intent, mitigation_action)
                        
                        while cas_result == self.cas_client.PARTIAL:
                            mitigation_action = self.cas_client.tune_mitigation(mitigation_action)
                            self._store.association_update(threat.uid, mitigation_action)
                            cas_result = self.cas_client.validate(intent, mitigation_action)

                        if cas_result == self.cas_client.INVALID:
                            logger.debug(f"Mitigation {mitigation_action.uid} was rejected by CAS. Setting as NEW for new cycle.")
                            threat.update_status(DetectedThreat.ThreatStatus.NEW)
                        
                        if cas_result == self.cas_client.VALID:
                            logger.debug(f"Mitigation {mitigation_action.uid} was accepted by CAS. Sending to RTR and setting UNDER_MITIGATION.")
                            self.rtr_client.enforce_mitigation(intent, mitigation_action)
                            threat.update_status(DetectedThreat.ThreatStatus.UNDER_MITIGATION)

                    else:
                        # Results from the DT are bad
                        logger.debug(f"Mitigation NOT effective for threat {threat.uid}. Setting as NEW for new cycle.")
                        threat.update_status(DetectedThreat.ThreatStatus.NEW)

                    # Remove the completed DT job
                    self._store.dt_job_delete(threat.uid)
                

            if threat.get_status() == DetectedThreat.ThreatStatus.REINCIDENT:
                # If threat is Reincident, propose a new mitigation action
                logger.debug(f"Processing threat: {threat.uid} (Status: REINCIDENT). Setting as NEW for new cycle.")
                threat.update_status(DetectedThreat.ThreatStatus.NEW)
                pass

