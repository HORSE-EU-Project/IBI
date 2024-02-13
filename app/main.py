from fastapi import FastAPI
from pydantic import BaseModel, Field
import uvicorn
import intent_manager
import delete_intents
from elasticsearch import Elasticsearch
import whatif_loop
import yaml
import empty_intent_store

with open('/code/app/config.yml') as f:
    parameters = yaml.safe_load(f)
host = parameters['ip']
port = parameters['port']
elastic_host = parameters['elasticsearch_ip']
elastic_port = parameters['elasticsearch_port']
elasticsearch_url = "http://" + elastic_host + ":" + elastic_port
es = Elasticsearch(elasticsearch_url)

#whatif_send_url = "http://" + host + ":" + port + parameters['to_send_whatif']
whatif_receive_url = "http://" + host + ":" + port + parameters['to_receive_whatif']
whatif_send_url = parameters['san_api_url']

#clears the existing intent store if you chose that in the config file
if parameters['clear_intent_store'] == 'true':
    empty_intent_store.empty_fun()
    print('cleared')

#CREATE THE APIs FIRST
app = FastAPI()
print('creating APIs')

#API for receiving intents from the DTE
class Intent(BaseModel):
    intent_type: str
    threat: str
    host: list
    duration: int

intents = [Intent(intent_type='', threat='', host=[], duration=0)]

intent_endpoint = parameters['to_enter_intents']
@app.get(intent_endpoint)
def get_intents():
    return intents

@app.post(intent_endpoint, status_code=201)
def add_intent(intent: Intent):
    intents.append(intent)
    return intent

@app.put(intent_endpoint)
def replace_intent(intent: Intent):
    intents.clear()
    intents.append(intent)
    #calls the intent manager function
    intent.duration = str(intent.duration)
    intent_manager.execute_intent_manager(intent, host)
    return intent


#API for sending workflows to the RTR
class Workflow(BaseModel):
    command: str
    intent_type: str
    threat: str
    attacked_host: str
    mitigation_host: str
    action: str
    duration: str
    intent_id: str

workflows = [Workflow(command='', intent_type='', threat='', attacked_host='',
                      mitigation_host='', action='', duration='', intent_id='')]

workflow_endpoint = parameters['to_send_workflow']
@app.get(workflow_endpoint)
def get_workflow():
    return workflows

@app.post(workflow_endpoint, status_code=201)
def add_workflow(workflow: Workflow):
    workflows.append(workflow)
    return workflow

@app.put(workflow_endpoint)
def replace_workflow(workflow: Workflow):
    workflows.clear()
    workflows.append(workflow)
    return workflow


#API for sending what-if question to the SAN
class Whatif_send(BaseModel):
    command: str
    intent_type: str
    threat: str
    host: list
    action: str
    duration: str
    id: str

whatif_sends = [Whatif_send(command='', intent_type='', threat='', host=[],
            action='', duration='', id='')]

whatif_sends_endpoint = parameters['to_send_whatif']
@app.get(whatif_sends_endpoint)
def get_whatif_send():
    return whatif_sends

@app.post(whatif_sends_endpoint, status_code=201)
def add_whatif_send(whatif_send: Whatif_send):
    whatif_sends.append(whatif_send)
    return whatif_send

@app.put(whatif_sends_endpoint)
def replace_whatif_send(whatif_send: Whatif_send):
    whatif_sends.clear()
    whatif_sends.append(whatif_send)
    return whatif_send


#API for receiving what-if answer from the SAN
class Whatif_receive(BaseModel):
    command: str
    intent_type: str
    threat: str
    host: list
    action: str
    duration: str
    id: str
    what_if_response: str


whatif_receives = [Whatif_receive(command='', intent_type='', threat='', host=[], action='',
                    duration='', id='', what_if_response='')]

whatif_receives_endpoint = parameters['to_receive_whatif']
@app.get(whatif_receives_endpoint)
def get_whatif_receive():
    return whatif_receives

@app.post(whatif_receives_endpoint, status_code=201)
def add_whatif_receive(whatif_receive: Whatif_receive):
    whatif_receives.append(whatif_receive)
    return whatif_receive

@app.put(whatif_receives_endpoint)
def replace_whatif_receive(whatif_receive: Whatif_receive):
    whatif_receives.clear()
    whatif_receives.append(whatif_receive)
    whatif_loop.whatif_receive_fun(whatif_receive, host)
    return whatif_receive


#API for storing and deleting existing intents
def _find_next_id():
    if len(stored_intents) == 0:
        next_id = 1
    else:
        next_id = max(stored_intent.id for stored_intent in stored_intents) + 1
    return next_id
class Stored_intent(BaseModel):
    id: int = Field(default_factory=_find_next_id, alias="id")
    intent_type: str
    threat: str
    host: str
    action: str
    duration: str
    intent_id: str
    priority: str

stored_intents = [Stored_intent(id=0, intent_type='', threat='', host='', action='',
                                duration='', intent_id='', priority='')]

stored_intents_endpoint = parameters['to_view_or_delete_intents']
@app.get(stored_intents_endpoint)
def get_stored_intent():
    return stored_intents

@app.post(stored_intents_endpoint, status_code=201)
def add_stored_intent(stored_intent: Stored_intent):
    if _find_next_id() == 1:
        stored_intents.clear()
        stored_intents.append(stored_intent)
    else:
        stored_intents.append(stored_intent)
    return stored_intent

@app.put(stored_intents_endpoint)
def replace_stored_intent(stored_intent: Stored_intent):
    stored_intents.clear()
    stored_intents.append(stored_intent)
    return stored_intent

del_stored_intents_endpoint = stored_intents_endpoint + "/{idx}"
@app.delete(del_stored_intents_endpoint)
def delete_stored_intent(idx: int):
    global to_delete_ind
    for i in range(len(stored_intents)):
        if stored_intents[i].id == idx:
            to_delete_ind = i
    to_delete = {}
    to_delete['intent_type'] = stored_intents[to_delete_ind].intent_type
    to_delete['threat'] = stored_intents[to_delete_ind].threat
    to_delete['host'] = stored_intents[to_delete_ind].host
    to_delete['action'] = stored_intents[to_delete_ind].action
    to_delete['duration'] = stored_intents[to_delete_ind].duration
    to_delete['intent_id'] = stored_intents[to_delete_ind].intent_id
    to_delete['priority'] = stored_intents[to_delete_ind].priority
    delete_intents.select_delete_fun(to_delete)
    del stored_intents[to_delete_ind]
    for i in range(len(stored_intents)):
        stored_intents[i].id = i + 1
    return {"message": "intent deleted"}


if __name__ == "__main__":
    uvicorn.run("main:app", host=host, port=int(port), reload=True)
