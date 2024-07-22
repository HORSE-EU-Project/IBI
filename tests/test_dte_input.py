import requests
import json

base_url = "http://localhost:7777/intents"

def test_dte_input_1():
    # Data to send to IBI as input
    data = {
        "intent_type": "mitigation",
        "threat": "ddos_dns",
        "host": ['dns-c6'],
        "duration": 9650
    }
    # Send a GET request to the "/items/" endpoint
    response = requests.put(f"{base_url}", json=data)
    # Assert that the response status code is 200 (OK)
    assert response.status_code == 200


def test_dte_input_2():
    # Data to send to IBI as input
    data = {
        "intent_type": "mitigation",
        "threat": "ddos_dns",
        "host": ['dns-c1', 'dns-c2', 'dns-c4', 'gnb', 'upf'],
        "duration": 3000
    }
    # Send a GET request to the "/items/" endpoint
    response = requests.put(f"{base_url}", json=data)
    # Assert that the response status code is 200 (OK)
    assert response.status_code == 200


def test_dte_input_3():
    # Data to send to IBI as input
    data =   {
        "intent_type": "mitigation",
        "threat": "ddos_dns",
        "host": ['dns-c6', 'dns-c8'],
        "duration": 400
    }
    # Send a GET request to the "/items/" endpoint
    response = requests.put(f"{base_url}", json=data)
    # Assert that the response status code is 200 (OK)
    assert response.status_code == 200

