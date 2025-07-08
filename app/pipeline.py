from constants import Const
from intent_manager import IntentManager
from db.elastic_search import ElasticSearchClient
from utils.log_config import setup_logging
from integrations.external import CKB

logger = setup_logging(__file__)

class IntentPipeline:

    def __init__(self):
        self.to_process = {}
        self.intent_manager = IntentManager()

    def process_intents(self):
        # Get intents with status 'new'
        logger.info("Starting intent pipeline iteration")
        try:
            logger.info("Checking new intents")
            intents = self.intent_manager.get_all(status=Const.INTENT_STATUS_NEW)
            for intent in intents:
                # Processing mitigation intents
                if intent.get("intent_type") == Const.INTENT_TYPE_MITIGATION:
                    logger.info(f"Processing intent ID: {intent.get('id')}, TYPE: {intent.get('intent_type')}")
                    # Set status of intent to "processing"
                    # Query cKB
                    ckb = CKB()
                    ckb.query_ckb(intent.get("threat"))

                    # Get mitigation actions from recommender
                    

                    # Validate with CAS

                    # Send to RTR

                    # Set status of intent to "under mitigation"
                    self.intent_manager.update_status(
                        intent.get("id"), 
                        Const.INTENT_STATUS_UNDER_MITIGATION
                    )
                
                if intent.get("intent_type") == Const.INTENT_TYPE_PREVENTION:
                    logger.info(f"Processing intent ID: {intent.get('id')}, TYPE: {intent.get('intent_type')}")
                    # Set status of intent to "processing"
                    # Query cKB
                    ckb = CKB()
                    ckb.query_ckb(intent.get("threat"))

                    # Get prevention actions from recommender

                    # Validate with CAS

                    # Send to RTR

                    # Set status of intent to "under mitigation"
                    self.intent_manager.update_status(
                        intent.get("id"), 
                        Const.INTENT_STATUS_MITIGATED
                    )

            
        except Exception as e:
            logger.error(f"Error querying Elasticsearch: {e}")
        
        # Set intents "under mitigation" that reached timeout to "mitigated"