import send_workflows

def delete_intents_fun(intent_id, workflow_url):
    #when an intent is deleted, a json containing the id of the intent is sent to the workflow api
    delete_dict = {
        "command": "delete_intent",
        "intent_type": "",
        "threat": "",
        "host": "",
        "action": "",
        "time_frame": "",
        "intent_id": intent_id
    }
    #print('delete dict: ', delete_dict)
    send_workflows.send_workflow_fun(workflow_url, delete_dict)
