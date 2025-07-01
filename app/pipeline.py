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
        try:
            logger.info("Starting intent pipeline iteration")
            intents = self.intent_manager.get_all(status=Const.INTENT_STATUS_NEW)
            for intent in intents:
                logger.info(f"Processing intent {intent.get("id")} ")

                # Query cKB
                ckb = CKB()
                ckb.query_ckb(intent.get("threat"))



            
        except Exception as e:
            logger.error(f"Error querying Elasticsearch: {e}")
        