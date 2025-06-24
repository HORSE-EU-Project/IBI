from integrations.external import RTR

def delete_intents_fun(intent_id, workflow_url):
    #when an intent is deleted, a json containing the id of the intent is sent to the workflow api
    delete_dict = {
        "command": "delete",
        "intent_type": "",
        "threat": "",
        "attacked_host": "",
        "mitigation_host": "",
        "action": "",
        "duration": "",
        "intent_id": intent_id,
        "status": "pending",
        "info": "to be enforced"
    }
    #print('delete dict: ', delete_dict)
    RTR().send_workflow(delete_dict)
