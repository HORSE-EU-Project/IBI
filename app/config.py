import yaml
from elasticsearch import Elasticsearch

files_directory = '/code/app/'
yml_file = files_directory + 'config.yml'
with open(yml_file) as f:
    parameters = yaml.safe_load(f)
host = parameters['ip']
port = parameters['port']
elastic_host = parameters['elasticsearch_ip']
elastic_port = parameters['elasticsearch_port']
elasticsearch_url = "http://" + elastic_host + ":" + elastic_port
es = Elasticsearch(elasticsearch_url)

whatif_receive_url = "http://" + host + ":" + port + parameters['to_receive_whatif']
whatif_send_url = parameters['san_api_url']
workflow_url = parameters['rtr_api_url']
intents_url = parameters['intents_url']
stored_intents_url = parameters['stored_intents_url']
qos_intents_url = parameters['qos_intents_url']
stored_qos_intents_url = parameters['stored_qos_intents_url']

templates_directory = files_directory + parameters['templates_directory']
static_directory = files_directory + parameters['static_directory']
policy_store_directory = files_directory + parameters['policy_store_file']

ddos_ntp = parameters['ddos_ntp']
ddos_dns = parameters['ddos_dns']
ddos_pfcp = parameters['ddos_pfcp']

qos_requirements = parameters['qos_requirements']