import requests
import colors
import config
import connect_rtr

parameters = config.parameters
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
    #login request
    access_token = connect_rtr.login_rtr(workflow_url)
    headers_for_action_post = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }
    #post action
    requests.post(f"{workflow_url}/actions", headers=headers_for_action_post, json=workflow)
    #print(response.json())
    #print('sent data: ', workflow)
    to_output = 'sent data: ' + str(workflow)
    with colors.pretty_output(colors.BOLD, colors.FG_GREEN) as out:
        out.write(to_output)