import requests
import logging

base_url = "http://localhost:8000/intents"

run_tests = [
    "test_demo0"
]

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_demo0():
    """
    Test case for Demo0
    """
    # Data to send to IBI as input
    data = {
        "intent_type": "mitigation",
        "threat": "helloworld",
        "host": [""],
        "duration": 600
    }
    # Send a GET request to the "/items/" endpoint
    response = requests.post(f"{base_url}", json=data)
    logger.info(f"Response: {response.text}")
    # Assert that the response status code is 200 (OK)
    assert response.status_code == 201




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
        "intent_type": "prevention",
        "threat": "ddos_dns",
        "host": ['dns-c6', 'dns-c8'],
        "duration": 400
    }
    # Send a GET request to the "/items/" endpoint
    response = requests.put(f"{base_url}", json=data)
    # Assert that the response status code is 200 (OK)
    assert response.status_code == 200

if __name__ == "__main__":
    for test in run_tests:
        logger.info(f"Running test: {test}")
        exec(f"{test}()")

