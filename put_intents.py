import requests
import sys

#IP address of the machine on which the IBI is running
host = sys.argv[1]

#url to send intents
#api_url = "http://192.168.56.1:7777/intents"
api_url = "http://" + host + ":7777/intents"

intent_dict_main = {
    "intent_type": "mitigation",
    "threat": "ddos",
    "host": ['192.168.56.5', '192.168.56.3'],
    "time_frame": "600"
}
response = requests.put(api_url, json=intent_dict_main)
#print(response.json())