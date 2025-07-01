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
                logger.info(f"Processing intent {intent.get("id")} ")
                # Set status of intent to "processing"

                # Query cKB
                ckb = CKB()
                ckb.query_ckb(intent.get("threat"))

                # Get mitigation actions from recommender

                # Validate with CAS

                # Send to RTR

                # Set status of intent to "under mitigation"
            
        except Exception as e:
            logger.error(f"Error querying Elasticsearch: {e}")
        
        # Set intents "under mitigation" that reached timeout to "mitigated"