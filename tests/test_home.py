import requests

def test_home_page():
    base_url = "http://localhost:7777/gui/"
    
    # Send a GET request to the "/items/" endpoint
    response = requests.get(f"{base_url}")
    
    # Assert that the response status code is 200 (OK)
    assert response.status_code == 200
    
    # Assert that the response contains the expected list of items
    # assert "IBI Dashboard" in response.text
    assert("IBI Dashboard" in response.text)