from elasticsearch import Elasticsearch
import config

class ElasticSearchClient:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ElasticSearchClient, cls).__new__(cls)
            cls._instance._init_client()
        return cls._instance

    def _init_client(self):
        self.client = Elasticsearch(
            config.elasticsearch_url,
            retry_on_timeout=True,
            max_retries=3
        )

    def get_client(self):
        return self.client