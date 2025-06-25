from elasticsearch import Elasticsearch
import config

es_client = Elasticsearch(
    config.elasticsearch_url, 
    retry_on_timeout=True,
    max_retries=3
)