from fastapi import FastAPI
from pydantic import BaseModel, Field
import uvicorn
import sys
import os
#import get_intents
import intent_manager
import delete_intents
#import time
#import pandas as pd
#import delete_command
from elasticsearch import Elasticsearch

host = sys.argv[1]
#host = "192.168.56.1"
#host = "172.21.0.1"
port = 7777
elasticsearch_url = "http://" + host + ":9200"
es = Elasticsearch(elasticsearch_url)

#delete existing data on the intent store on elasticsearch when u start new deployment
int_ind = False
for i in list(range(100)):
    intent_index = es.exists(index="stored_intents", id=i, doc_type=None, params=None, headers=None)
    if intent_index == True:
        int_ind = True
if int_ind == True:
    resp = es.search(index="stored_intents", query={"match_all": {}})
    total = resp['hits']['total']['value']
    print('total: ', total)
    if total != 0:
        id_arr = []
        for hit in resp['hits']['hits']:
            id_arr.append(hit["_id"])
        print('id arr: ', id_arr)
        for id in id_arr:
            es.delete(index="stored_intents", id=id)
resp = es.search(index="stored_intents", query={"match_all": {}})
total = resp['hits']['total']['value']
print('total after: ', total)

#delete any old local storage intent store whenever u start a new deployment
intent_store = 'intent_store.csv'
if (os.path.exists(intent_store) and os.path.isfile(intent_store)):
    os.remove(intent_store)
#CREATE THE API FIRST
app = FastAPI()

print('creating APIs')

class Intent(BaseModel):
    intent_type: str
    threat: str
    host: list
    time_frame: str

intents = [Intent(intent_type='', threat='', host=[], time_frame='')]

@app.get("/intents")
def get_intents():
    return intents

@app.post("/intents", status_code=201)
def add_intent(intent: Intent):
    intents.append(intent)
    return intent

@app.put("/intents")
def replace_intent(intent: Intent):
    intents.clear()
    intents.append(intent)
    #calls the intent manager function
    intent_manager.execute_intent_manager(intent, host)
    return intent



class Workflow(BaseModel):
    command: str
    intent_type: str
    threat: str
    host: str
    action: str
    time_frame: str
    intent_id: str

workflows = [Workflow(command='', intent_type='', threat='', host='', action='', time_frame='', intent_id='')]

@app.get("/workflows")
def get_workflow():
    return workflows

@app.post("/workflows", status_code=201)
def add_workflow(workflow: Workflow):
    workflows.append(workflow)
    return workflow

@app.put("/workflows")
def replace_workflow(workflow: Workflow):
    workflows.clear()
    workflows.append(workflow)
    return workflow


class Whatif_send(BaseModel):
    command: str
    intent_type: str
    threat: str
    host: list
    action: str
    time_frame: str

whatif_sends = [Whatif_send(command='', intent_type='', threat='', host=[], action='', time_frame='')]

@app.get("/whatif_sends")
def get_whatif_send():
    return whatif_sends

@app.post("/whatif_sends", status_code=201)
def add_whatif_send(whatif_send: Whatif_send):
    whatif_sends.append(whatif_send)
    return whatif_send

@app.put("/whatif_sends")
def replace_whatif_send(whatif_send: Whatif_send):
    whatif_sends.clear()
    whatif_sends.append(whatif_send)
    return whatif_send



class Whatif_receive(BaseModel):
    command: str
    intent_type: str
    threat: str
    host: list
    action: str
    time_frame: str
    what_if_response: str


whatif_receives = [Whatif_receive(command='', intent_type='', threat='', host=[], action='', time_frame='', what_if_response='')]

@app.get("/whatif_receives")
def get_whatif_receive():
    return whatif_receives

@app.post("/whatif_receives", status_code=201)
def add_whatif_receive(whatif_receive: Whatif_receive):
    whatif_receives.append(whatif_receive)
    return whatif_receive

@app.put("/whatif_receives")
def replace_whatif_receive(whatif_receive: Whatif_receive):
    whatif_receives.clear()
    whatif_receives.append(whatif_receive)
    return whatif_receive


def _find_next_id():
    return max(stored_intent.id for stored_intent in stored_intents) + 1
class Stored_intent(BaseModel):
    id: int = Field(default_factory=_find_next_id, alias="id")
    intent_type: str
    threat: str
    host: str
    action: str
    time_frame: str
    intent_id: str

stored_intents = [Stored_intent(id=0, intent_type='', threat='', host='', action='', time_frame='', intent_id='')]

@app.get("/stored_intents")
def get_stored_intent():
    return stored_intents

@app.post("/stored_intents", status_code=201)
def add_stored_intent(stored_intent: Stored_intent):
    if _find_next_id() == 1:
        stored_intents.clear()
        stored_intents.append(stored_intent)
    else:
        stored_intents.append(stored_intent)
    return stored_intent

@app.put("/stored_intents")
def replace_stored_intent(stored_intent: Stored_intent):
    stored_intents.clear()
    stored_intents.append(stored_intent)
    return stored_intent

@app.delete("/stored_intents/{idx}")
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
    to_delete['time_frame'] = stored_intents[to_delete_ind].time_frame
    to_delete['intent_id'] = stored_intents[to_delete_ind].intent_id
    delete_intents.select_delete_fun(to_delete, host)
    del stored_intents[to_delete_ind]
    for i in range(len(stored_intents)):
        stored_intents[i].id = i + 1
    return {"message": "intent deleted"}


if __name__ == "__main__":
    uvicorn.run("start:app", host=host, port=port, reload=True)
