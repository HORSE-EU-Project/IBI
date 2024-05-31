import requests
import colors

#the function used to send workflow or data to an api
def send_workflow_fun(workflow_url, workflow):
    requests.put(workflow_url, json=workflow)
    #print(response.json())
    print('SENT DATA: ', workflow)
    to_output = 'sent data: ' + str(workflow)
    with colors.pretty_output(colors.BOLD, colors.FG_GREEN) as out:
        out.write(to_output)
