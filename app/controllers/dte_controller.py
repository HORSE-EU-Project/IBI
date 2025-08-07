from data.store import InMemoryStore
from models.api_models import DTEIntent
from models.core_models import CoreIntent
from utils.log_config import setup_logging

logger = setup_logging(__name__)

class DTEController:

    RETURN_STATUS_CREATED = "RETURN_STATUS_CREATED"
    RETURN_STATUS_UPDATED = "RETURN_STATUS_UPDATED"

    def __init__(self):
        self._storage = InMemoryStore()

    def process_dte_intent(self, dte_intent: DTEIntent):
        """
        Process an intent request.
        If the intent already exists, it updates the status.
        If it does not exist, it creates a new intent.
        """
        logger.info(f"Processing intent request from DTE: {dte_intent}")

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
        
        # System state regarding threads must be always updated
        # TODO: update system state
        