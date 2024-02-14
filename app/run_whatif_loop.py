from elasticsearch import Elasticsearch
import whatif_loop
import yaml
import warnings
warnings.filterwarnings('ignore')

with open('/code/app/config.yml') as f:
    parameters = yaml.safe_load(f)
print('parameters: ', parameters)
host = parameters['ip']
port = parameters['port']
elastic_host = parameters['elasticsearch_ip']
elastic_port = parameters['elasticsearch_port']
elasticsearch_url = "http://" + elastic_host + ":" + elastic_port
es = Elasticsearch(elasticsearch_url)
#whatif_send_url = "http://" + host + ":" + port + parameters['to_send_whatif']
whatif_send_url = parameters['san_api_url']

whatif_loop.whatif_loop_fun(es, whatif_send_url)
