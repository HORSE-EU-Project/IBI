import requests
import sys

#IP address of the machine on which the IBI is running
host = sys.argv[1]

#api_url = "http://192.168.56.1:7780/workflows"
api_url = "http://" + host + ":7777/whatif_receives"

whatif_reply = {
	"command":"",
	"intent_type":"",
	"threat":"",
	"host":[],
	"action":"",
	"time_frame":"",
	"what_if_response": "ok"
	}
response = requests.put(api_url, json=whatif_reply)
#print(response.json())



