#!/usr/bin/python3

import requests
import json

BASE_URL = "http://localhost:7777/intents"

def send_qod_intent():
    # Data to send to IBI as input
    data = {
        'intent_type': 'qos_dns',
        'name': 'latency',
        'value': 0.2,
        'unit': 'ms',
        'host': ['dns-c2', 'dns-c1']
    }
    # Send a GET request to the "/items/" endpoint
    response = requests.put( f"{BASE_URL}", json=json.dumps(data) )
    # Assert that the response status code is 200 (OK)
    assert response.status_code == 200

if __name__ == "__main__":
    print("Sending a QoS Intent to IBI")
    send_qod_intent()