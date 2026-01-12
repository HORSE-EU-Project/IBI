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
HORSE IBI configuration
"""
IBI_LOG_LEVEL = parameters["ibi"]["log_level"]

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
RTR_FORCE_IP = parameters["rtr"].get("force_ip", False)


"""
External Syslog server (SIAM Integration)
"""
SYSLOG_IP = parameters["syslog"]["ip"]
SYSLOG_PORT = parameters["syslog"].get("port", 514)  # Default syslog port is 514

"""
Mitigation Actions configuration
"""
MITIGATION_ACTIONS = parameters.get("mitigation_actions", [])
MITIGATION_HOST = parameters.get("mitigation_host", [])

# HORSE Component Status
MODULE_STATUS = parameters["module-status"]

# Should use IPs instead of hostnames for RTR?
RESOLVE_HOSTNAMES = parameters.get("ibi").get("resolve_hostnames", False)
IP_MAPPINGS = parameters.get("ip_mappings", [])

