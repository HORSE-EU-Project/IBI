import requests
import colors

#the function used to send workflow or data to an api
def send_workflow_fun(workflow_url, workflow):
    requests.put(workflow_url, json=workflow)
    #print(response.json())
    #print('SENT DATA: ', workflow)
    to_output = 'sent data: ' + str(workflow)
    with colors.pretty_output(colors.BOLD, colors.FG_GREEN) as out:
        out.write(to_output)

#the function used to send workflow or data to RTR api
def send_workflow_fun_2(workflow_url, workflow):
    #requests.put(workflow_url, json=workflow)
    ###################### LOGIN REQUESTS ######################
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    data = {
        'grant_type': '',
        'username': 'user1',
        'password': 'user1',
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

    headers_for_action_post = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    response_for_new_action = requests.post(f"{workflow_url}/actions", headers=headers_for_action_post, json=workflow)
    #print(response.json())
    #print('sent data: ', workflow)
    to_output = 'sent data: ' + str(workflow)
    with colors.pretty_output(colors.BOLD, colors.FG_GREEN) as out:
        out.write(to_output)