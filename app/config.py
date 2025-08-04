import yaml
import os
from urllib import parse

"""
Get current directory to derive application directory
Config file, template folder and Q-Learning files are 
placed a the project root directory
"""
current_dir = os.path.dirname(os.path.abspath(__file__))
# Remove the /app from the tail of the path
files_directory = os.path.dirname(current_dir)


yml_file = os.path.join(files_directory, "config.yml")
with open(yml_file) as f:
    parameters = yaml.safe_load(f)


"""
Expose the Elasticsearch connection parameters
"""
ES_HOST = parameters["elasticsearch"]["ip"]
ES_PORT = parameters["elasticsearch"]["port"]
ES_URL = f"http://{ES_HOST}:{ES_PORT}"
ES_CLEAN = parameters["elasticsearch"]["reset"]


"""
Knowledge Base (CKB) connection parameters
"""
CKB_URL = parameters["ckb"]["url"]

"""
IADT (Impact analysis DT) connection parameters
"""
IADT_URL = parameters["iadt"]["url"]

"""
CAS (Compliance Assessment) connection parameters
"""
CAS_URL = parameters["cas"]["url"]

"""
RTR Connection parameters
"""
# Integration with the RTR
RTR_URL = parameters["rtr"]["url"]
RTR_USER = parameters["rtr"]["username"]
RTR_PASSWORD = parameters["rtr"]["password"]
RTR_EMAIL = parameters["rtr"]["email"]



# whatif_receive_url = "http://" + host + ":" + port + parameters["to_receive_whatif"]
# whatif_send_url = parameters["san_api_url"]
# workflow_url = parameters["rtr_api_url"]
# intents_url = parameters["intents_url"]
# alerts_url = parameters["alerts_url"]
# stored_intents_url = parameters["stored_intents_url"]
# qos_intents_url = parameters["qos_intents_url"]
# stored_qos_intents_url = parameters["stored_qos_intents_url"]
# rtr_username = parameters["rtr_username"]
# rtr_password = parameters["rtr_password"]
# rtr_email = parameters["rtr_email"]
# to_connect_to_rtr = parameters["to_connect_to_rtr"]

# templates_directory = files_directory + parameters["templates_directory"]
# static_directory = files_directory + parameters["static_directory"]
# policy_store_directory = files_directory + parameters["policy_store_file"]

# ddos_ntp = parameters["ddos_ntp"]
# ddos_dns = parameters["ddos_dns"]
# ddos_pfcp = parameters["ddos_pfcp"]

# rate_req = parameters["req/s"]
# qos_requirements = parameters["qos_requirements"]

# hosts = parameters["hosts"]
# links = parameters["links"]
