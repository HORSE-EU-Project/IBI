from multiprocessing import Process
from fastapi import FastAPI
from pydantic import BaseModel, Field
import uvicorn
import intent_manager
import alert_box
import delete_intents
import whatif_loop
import empty_intent_store
import run_loops
from flask import Flask, request, render_template
from fastapi.middleware.wsgi import WSGIMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import config
import get_intents_script
import requests


parameters = config.parameters
host = config.host
port = config.port
intents_url = config.intents_url
stored_intents_url = config.stored_intents_url
qos_intents_url = config.qos_intents_url
stored_qos_intents_url = config.stored_qos_intents_url
workflow_url = config.workflow_url

# #clears the existing intent store if you chose that in the config file
# if parameters['clear_intent_store'] == 'true':
#     empty_intent_store.empty_fun()
#     print('cleared')

templates_directory = config.templates_directory
#flask app
flask_app = Flask(__name__,template_folder=templates_directory)
app = FastAPI()

#CREATE THE APIs FIRST
print('creating APIs')

@app.get('/')
def first_page():
    #execute_qos()
    # If the user reaches the root document, it redirects the user to
    # the GUI
    return RedirectResponse("/gui")

#API for receiving alerts from the DTE
class Alert(BaseModel):
    alert_type: str
    threat: str
    host: list
    duration: int

alerts = [Alert(alert_type='', threat='', host=[], duration=0)]

alert_endpoint = parameters['to_enter_alerts']
@app.get(alert_endpoint)
def get_alerts():
    #execute_qos()
    return alerts

@app.post(alert_endpoint, status_code=201)
def add_alert(alert: Alert):
    alerts.append(alert)
    #execute_qos()
    return alert

@app.put(alert_endpoint)
def replace_alert(alert: Alert):
    alerts.clear()
    alerts.append(alert)
    #calls the intent manager function
    alert.duration = str(alert.duration)
    #execute_qos()
    alert_box.execute_alert_box(alert)
    return alert


#API for receiving intents
class Intent(BaseModel):
    intent_type: str
    threat: str
    host: list
    duration: int

intents = [Intent(intent_type='', threat='', host=[], duration=0)]

intent_endpoint = parameters['to_enter_intents']
 
def get_intents():
    #execute_qos()
    return intents

@app.post(intent_endpoint, status_code=201)
def add_intent(intent: Intent):
    intents.append(intent)
    #execute_qos()
    return intent

@app.put(intent_endpoint)
def replace_intent(intent: Intent):
    intents.clear()
    intents.append(intent)
    #calls the intent manager function
    intent.duration = str(intent.duration)
    #execute_qos()
    intent_manager.execute_intent_manager(intent)
    return intent


#API for receiving QOS intents that should not be violated
class qos_Intent(BaseModel):
    intent_type: str
    name: str
    value: float
    unit: str
    host: list

qos_intents = [qos_Intent(intent_type='', name='', value=0.0, unit='', host=[])]

qos_intent_endpoint = parameters['to_enter_qos_intents']
@app.get(qos_intent_endpoint)
def get_qos_intents():
    #execute_qos()
    return qos_intents

@app.post(qos_intent_endpoint, status_code=201)
def add_qos_intent(qos_intent: qos_Intent):
    qos_intents.append(qos_intent)
    #execute_qos()
    return qos_intent

@app.put(qos_intent_endpoint)
def replace_qos_intent(qos_intent: qos_Intent):
    qos_intents.clear()
    qos_intents.append(qos_intent)
    #calls the intent manager function
    qos_intent.value = float(qos_intent.value)
    #execute_qos()
    intent_manager.execute_intent_manager_qos(qos_intent)
    return qos_intent

#API for sending what-if question to the SAN
class Whatif_send(BaseModel):
    #command: str
    id: str
    topology_name: str
    attack: str
    what_condition: dict
    if_condition: dict
    #duration: str
    #kpi_measured: str
    #prevention_host: str
    #interface: str
    #host_references: dict

#whatif_sends = [Whatif_send(command='', intent_type='', threat='', host='',
#            action='', duration='', id='', kpi_measured='', prevention_host='')]
                           #interface='', host_references={})]
whatif_sends = [Whatif_send(id='', topology_name='', attack='', what_condition={},
            if_condition={})]

whatif_sends_endpoint = parameters['to_send_whatif']
@app.get(whatif_sends_endpoint)
def get_whatif_send():
    return whatif_sends

@app.post(whatif_sends_endpoint, status_code=201)
def add_whatif_send(whatif_send: Whatif_send):
    #whatif_send.what_condition = whatif_send.what-condition
    #delattr(whatif_send, 'person_name')
    whatif_sends.append(whatif_send)
    return whatif_send

@app.put(whatif_sends_endpoint)
def replace_whatif_send(whatif_send: Whatif_send):
    whatif_sends.clear()
    whatif_sends.append(whatif_send)
    return whatif_send

#API for receiving what-if answer from the SAN
class Whatif_receive(BaseModel):
    id: str
    topology_name: str
    attack: str
    what: dict
    #host: str
    #kpi_measured: str
    #kpi_value: str
    #kpi_unit: str


#whatif_receives = [Whatif_receive(id='', host='', kpi_measured='', kpi_value='',
#                                  kpi_unit='')]
whatif_receives = [Whatif_receive(id='', topology_name='', attack='', what={})]

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
    whatif_loop.whatif_receive_fun(whatif_receive)
    return whatif_receive


#API for receiving what-if answer from the SAN
'''class Whatif_receive(BaseModel):
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
    whatif_loop.whatif_receive_fun(whatif_receive)
    return whatif_receive'''


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
    #execute_qos()
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
def delete_stored_intent(idx: str):
    global to_delete_ind
    to_delete_ind = 'no_index'
    for i in range(len(stored_intents)):
        if stored_intents[i].intent_id == idx:
            to_delete_ind = i
    if to_delete_ind != 'no_index':
        to_delete = {}
        to_delete['intent_type'] = stored_intents[to_delete_ind].intent_type
        to_delete['threat'] = stored_intents[to_delete_ind].threat
        to_delete['host'] = stored_intents[to_delete_ind].host
        to_delete['action'] = stored_intents[to_delete_ind].action
        print('stored intents action: ', stored_intents[to_delete_ind].action)
        to_delete['duration'] = stored_intents[to_delete_ind].duration
        to_delete['intent_id'] = stored_intents[to_delete_ind].intent_id
        to_delete['priority'] = stored_intents[to_delete_ind].priority
        delete_intents.select_delete_fun(to_delete)
        del stored_intents[to_delete_ind]
        for i in range(len(stored_intents)):
            stored_intents[i].id = i + 1
        to_delete_ind = 'no_index'
        stored_intents_arr = get_intents_script.get_intent_fun(stored_intents_url)
        if len(stored_intents_arr) == 0:
            base_data = {'id': 0, 'intent_type': '', 'threat': '', 'host': '', 'action': '', 'duration': '',
                     'intent_id': '', 'priority': ''}
            requests.post(stored_intents_url, json=base_data)
        return {"message": "intent deleted"}
    else:
        #print('invalid delete request')
        return {"message": "invalid delete request"}



#API for storing and deleting existing QOS intents
def _find_next_id_qos():
    if len(stored_qos_intents) == 0:
        next_id = 1
    else:
        next_id = max(stored_qos_intent.id for stored_qos_intent in stored_qos_intents) + 1
    return next_id
class Stored_qos_intent(BaseModel):
    id: int = Field(default_factory=_find_next_id_qos, alias="id")
    intent_type: str
    name: str
    value: float
    unit: str
    host: str
    qos_intent_id: str

stored_qos_intents = [Stored_qos_intent(id=0, intent_type='', name='', value=0.0,
                                    unit='', host='', qos_intent_id='')]

stored_qos_intents_endpoint = parameters['to_view_or_delete_qos_intents']
@app.get(stored_qos_intents_endpoint)
def get_stored_qos_intent():
    #execute_qos()
    return stored_qos_intents

@app.post(stored_qos_intents_endpoint, status_code=201)
def add_stored_qos_intent(stored_qos_intent: Stored_qos_intent):
    if _find_next_id_qos() == 1:
        stored_qos_intents.clear()
        stored_qos_intents.append(stored_qos_intent)
    else:
        stored_qos_intents.append(stored_qos_intent)
    return stored_qos_intent

@app.put(stored_qos_intents_endpoint)
def replace_stored_qos_intent(stored_qos_intent: Stored_qos_intent):
    stored_qos_intents.clear()
    stored_qos_intents.append(stored_qos_intent)
    return stored_qos_intent

del_stored_qos_intents_endpoint = stored_qos_intents_endpoint + "/{idx}"
@app.delete(del_stored_qos_intents_endpoint)
def delete_stored_qos_intent(idx: str):
    global to_delete_ind
    to_delete_ind = 'no_index'
    for i in range(len(stored_qos_intents)):
        if stored_qos_intents[i].qos_intent_id == idx:
            to_delete_ind = i
    if to_delete_ind != 'no_index':
        to_delete = {}
        to_delete['intent_type'] = stored_qos_intents[to_delete_ind].intent_type
        to_delete['name'] = stored_qos_intents[to_delete_ind].name
        to_delete['value'] = stored_qos_intents[to_delete_ind].value
        to_delete['unit'] = stored_qos_intents[to_delete_ind].unit
        to_delete['host'] = stored_qos_intents[to_delete_ind].host
        to_delete['qos_intent_id'] = stored_qos_intents[to_delete_ind].qos_intent_id
        delete_intents.select_delete_fun_qos(to_delete)
        del stored_qos_intents[to_delete_ind]
        for i in range(len(stored_qos_intents)):
            stored_qos_intents[i].id = i + 1
        to_delete_ind = 'no_index'
        stored_qos_intents_arr = get_intents_script.get_intent_fun(stored_qos_intents_url)
        if len(stored_qos_intents_arr) == 0:
            base_data = {'id': 0, 'intent_type': '', 'name': '', 'value': 0.0,
                                    'unit': '', 'host': '', 'qos_intent_id': ''}
            requests.post(stored_qos_intents_url, json=base_data)
        return {"message": "qos intent deleted"}
    else:
        #print('invalid delete request')
        return {"message": "invalid delete request"}


def run_api_server():
    #uvicorn_url = 'http://' + host + ':' + port
    #print('App hosted on ', uvicorn_url)
    #uvicorn.run("main:app", host=host, port=int(port), reload=True, log_level='critical')
    uvicorn.run("main:app", host=host, port=int(port), reload=True)

def sched():
    run_loops.run_whatif_loop_fun()

def sched_2():
    run_loops.run_duration_check_loop()


if __name__ == "__main__":
    p1 = Process(target = run_api_server)
    #p2 = Process(target = sched)
    #p3 = Process(target=sched_2)
    p1.start()
    #p2.start()
    #p3.start()
    p1.join()
    #p2.join()
    #p3.join()