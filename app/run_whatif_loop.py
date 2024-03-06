from elasticsearch import Elasticsearch
import whatif_loop
import warnings
import config
warnings.filterwarnings('ignore')

def run_whatif_loop_fun():
    elasticsearch_url = config.elasticsearch_url
    es = Elasticsearch(elasticsearch_url)
    whatif_send_url = config.whatif_send_url
    whatif_loop.whatif_loop_fun(es, whatif_send_url)
