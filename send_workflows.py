import requests

#the function that sends the workflow to the workflow api
def send_workflow_fun(workflow_url, workflow):
    requests.put(workflow_url, json=workflow)
    #print(response.json())
    print('sent workflow: ', workflow)