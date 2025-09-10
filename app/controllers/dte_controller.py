from data.store import InMemoryStore
from models.api_models import DTEIntent
from models.core_models import CoreIntent, DetectedThreat
from integrations.siem import CustomSIEM
from utils.log_config import setup_logging

logger = setup_logging(__name__)

class DTEController:

    RETURN_STATUS_CREATED = "RETURN_STATUS_CREATED"
    RETURN_STATUS_UPDATED = "RETURN_STATUS_UPDATED"

    def __init__(self):
        self._storage = InMemoryStore()
        self._customSIEM = CustomSIEM()

    def get_all_intents(self):
        """
        Get all intents from the storage.
        """
        logger.debug("Fetching all intents from storage")
        return self._storage.intent_get_all()


    def process_dte_intent(self, dte_intent: DTEIntent):
        """
        Process an intent request.
        If the intent already exists, it updates the status.
        If it does not exist, it creates a new intent.
        """
        logger.info(f"Processing intent request from DTE: {dte_intent}")

        # Infere system state from the request
        # It a simlar threat exists, renew it, otherwise create a new one
        new_threat = DetectedThreat(dte_intent)
        existing_threat_uid = self._storage.threat_locate(new_threat)
        if existing_threat_uid:
            logger.info(f"Threat {existing_threat_uid} already exists.")
            updated_threat = self._storage.threat_get(existing_threat_uid)
            updated_threat.renew()
            self._storage.threat_update(existing_threat_uid, updated_threat)
            logger.info(f"Threat {existing_threat_uid} updated successfully.")
        else:
            logger.info(f"New threat detected: {new_threat.uid}")
            self._storage.threat_add(new_threat)
            # Generate a SIEM alarm
            self._customSIEM.send_log(new_threat, CustomSIEM.AlarmType.NEW)
            

        # Convert to a CoreIntent
        new_core_intent = CoreIntent(dte_intent)

        # Check if the intent already exists
        if self._storage.intent_exists(new_core_intent):
            logger.warning(f"Intent {new_core_intent.get_uid()} already exists. Updating threat state.")
            return self.RETURN_STATUS_UPDATED

        # Add the new intent to storage
        self._storage.intent_add(new_core_intent)
        logger.info(f"Intent {new_core_intent.get_uid()} created successfully.")
        return self.RETURN_STATUS_CREATED

    def delete_intent(self, intent_id: str):
        """
        Delete an intent from the storage.
        """
        self._storage.intent_remove(intent_id)