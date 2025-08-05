from elasticsearch import Elasticsearch
import config
from constants import Const
from utils.log_config import setup_logging
from threading import Lock


# Configure logging
logger = setup_logging(__name__)


class ESClientMeta(type):

    _instances = {}
    _lock: Lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
            return cls._instances[cls]
        
class ElasticSearchClient(metaclass=ESClientMeta):
    
    _es_client: None

    def __init__(self):
        """
        Initialize the Elasticsearch client.
        """
        self._es_client = Elasticsearch(
            config.ES_URL,
            headers={
                "Accept": "application/vnd.elasticsearch+json; compatible-with=8",
                "Content-Type": "application/vnd.elasticsearch+json; compatible-with=8"
            },
            retry_on_timeout=True,
            max_retries=3
        )
        logger.info("Elasticsearch client initialized")

    def get_client(self):
        """
        Get the Elasticsearch client instance.
        """
        return self._es_client
    

    def delete_indices(self):
        """
        Delete all indices in Elasticsearch.
        """
        _to_delete = {
            Const.INTENTS_INDEX, 
            Const.MITIGATION_INDEX,
            Const.ASSOCIATIONS_INDEX
        }

        for index in _to_delete:
            try:
                if self._es_client:
                    response = self._es_client.indices.delete(index=index, ignore=[404])
                    if response.get('acknowledged', False):
                        logger.debug(f"Index '{index}' deleted successfully")
                    else:
                        logger.warning(f"Failed to delete index '{index}'")
            except Exception as e:
                logger.error(f"Error deleting index '{index}': {str(e)}")

    
    def pupulate_mitigations(self):
        """
        Populate mitigations data in Elasticsearch.
        """
        # Check whether the index MITIGATION_INDEX exists
        if not self._es_client.indices.exists(index=Const.MITIGATION_INDEX):
            logger.info(f"Index '{Const.MITIGATION_INDEX}' does not exist, creating it")
            self._es_client.indices.create(index=Const.MITIGATION_INDEX)
            
        else:
            logger.info(f"Index '{Const.MITIGATION_INDEX}' already exists")
