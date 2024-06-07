import config
import requests

parameters = config.parameters
#the function used to register a user on the RTR api
def register_rtr(workflow_url):
    #requests.put(workflow_url, json=workflow)
    #REGISTER
    reg_headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json'
    }

    reg_data = {
        'username': parameters['rtr_username'],
        'email': parameters['rtr_email'],
        'password': parameters['rtr_password'],
    }
    # POST REGISTRATION REQUEST
    requests.post(f"{workflow_url}/register", headers=reg_headers, data=reg_data)

#Login
def login_rtr(workflow_url):
    #requests.put(workflow_url, json=workflow)
    ###################### LOGIN REQUESTS ######################
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = {
        'grant_type': '',
        'username': parameters['rtr_username'],
        'password': parameters['rtr_password'],
        'scope': '',
        'client_id': '',
        'client_secret': ''
    }
    # POST LOGIN REQUEST
    response = requests.post(f"{workflow_url}/login", headers=headers, data=data)

    # Assert that the response contains the expected list of items
    access_token = ''
    if 'access_token' in response.json():
        access_token = response.json()['access_token']
        print(f"Authentication token: {access_token}")

    return access_token