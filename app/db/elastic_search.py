from elasticsearch import Elasticsearch
import config
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
        if self._es_client:
            self._es_client.indices.delete(index="*", ignore=[400, 404])
            logger.debug("All indices deleted from Elasticsearch")
        else:
            logger.error("Elasticsearch client is not initialized")