import requests

#the function used to send workflow or data to an api
def send_workflow_fun(workflow_url, workflow):
    requests.put(workflow_url, json=workflow)
    #print(response.json())
    print('sent data: ', workflow)