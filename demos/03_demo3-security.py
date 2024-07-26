#!/usr/bin/python3

import requests
import json

BASE_URL = "http://localhost:7777/intents"


def send_qos_intent():
    # Data to send to IBI as input
    data = {
        "intent_type": "mitigation",
        "threat": "ddos_dns",
        "host": ["dns-c5", "dns-c2"],
        "duration": 9650,
    }
    # Send a GET request to the "/items/" endpoint
    response = requests.put(f"{BASE_URL}", json=data)
    # Assert that the response status code is 200 (OK)
    assert response.status_code == 200


if __name__ == "__main__":
    print("Sending Security Intent (1) to IBI")
    send_qos_intent()
