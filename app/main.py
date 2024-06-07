from multiprocessing import Process
from fastapi import FastAPI
from pydantic import BaseModel, Field
import uvicorn
import intent_manager
import delete_intents
import whatif_loop
import empty_intent_store
import run_whatif_loop
import warnings
from flask import Flask, request, render_template
from fastapi.middleware.wsgi import WSGIMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import config
import get_intents_script
import connect_rtr
import logging

warnings.filterwarnings('ignore')

parameters = config.parameters
host = config.host
port = config.port
intents_url = config.intents_url
stored_intents_url = config.stored_intents_url
qos_intents_url = config.qos_intents_url
stored_qos_intents_url = config.stored_qos_intents_url
workflow_url = config.workflow_url

access_token = ""

#if connection to rtr is set to true in the config file, then the user registers and logs in
if parameters['to_connect_to_rtr'] == 'true':
    connect_rtr.register_rtr(workflow_url)
    # access_token = connect_rtr.login_rtr(workflow_url)

    print('cleared')

#clears the existing intent store if you chose that in the config file
if parameters['clear_intent_store'] == 'true':
    empty_intent_store.empty_fun()
    print('cleared')

'''print(parameters['qos_requirements'])
# Turns a dictionary into a class
class my_object:
    def __init__(self, d=None):
        if d is not None:
            for key, value in d.items():
                setattr(self, key, value)
def execute_qos():
    for i in range(len(parameters['qos_requirements'])):
        print(parameters['qos_requirements'][i])
        intent_manager.execute_intent_manager_qos(my_object(parameters['qos_requirements'][i]), host)'''

templates_directory = config.templates_directory
#flask app
flask_app = Flask(__name__,template_folder=templates_directory)
# Disable request logging
#flask_app.logger.setLevel(logging.ERROR)
#fastAPI app
app = FastAPI()

#CREATE THE APIs FIRST
print('creating APIs')

@app.get('/')
def first_page():
    #execute_qos()
    # If the user reaches the root document, it redirects the user to
    # the GUI
    return RedirectResponse("/gui")

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
    intent_manager.execute_intent_manager(intent, access_token)
    return intent


#API for receiving QOS intents that should not be violated
class qos_Intent(BaseModel):
    intent_type: str
    name: str
    value: float
    host: list

qos_intents = [qos_Intent(intent_type='', name='', value=0.0, host=[])]

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


# #API for sending workflows to the RTR
# class Workflow(BaseModel):
#     command: str
#     intent_type: str
#     threat: str
#     attacked_host: str
#     mitigation_host: str
#     action: str
#     duration: str
#     intent_id: str

# workflows = [Workflow(command='', intent_type='', threat='', attacked_host='',
#                       mitigation_host='', action='', duration='', intent_id='')]

# workflow_endpoint = parameters['to_send_workflow']
# @app.get(workflow_endpoint)
# def get_workflow():
#     return workflows

# @app.post(workflow_endpoint, status_code=201)
# def add_workflow(workflow: Workflow):
#     workflows.append(workflow)
#     return workflow

# @app.put(workflow_endpoint)
# def replace_workflow(workflow: Workflow):
#     workflows.clear()
#     workflows.append(workflow)
#     return workflow


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
    whatif_loop.whatif_receive_fun(whatif_receive, access_token)
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
        to_delete['duration'] = stored_intents[to_delete_ind].duration
        to_delete['intent_id'] = stored_intents[to_delete_ind].intent_id
        to_delete['priority'] = stored_intents[to_delete_ind].priority
        delete_intents.select_delete_fun(to_delete)
        del stored_intents[to_delete_ind]
        for i in range(len(stored_intents)):
            stored_intents[i].id = i + 1
        to_delete_ind = 'no_index'
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
    host: str
    qos_intent_id: str

stored_qos_intents = [Stored_qos_intent(id=0, intent_type='', name='', value=0.0,
                                    host='', qos_intent_id='')]

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
        to_delete['host'] = stored_qos_intents[to_delete_ind].host
        to_delete['qos_intent_id'] = stored_qos_intents[to_delete_ind].qos_intent_id
        delete_intents.select_delete_fun_qos(to_delete)
        del stored_qos_intents[to_delete_ind]
        for i in range(len(stored_qos_intents)):
            stored_qos_intents[i].id = i + 1
        to_delete_ind = 'no_index'
        return {"message": "qos intent deleted"}
    else:
        #print('invalid delete request')
        return {"message": "invalid delete request"}


#FLASK

@flask_app.route('/')
def main():
    return render_template("index.html")

@flask_app.route('/index.html')
def Home():
    return render_template("index.html")

@flask_app.route('/ml_reco.html')
def ml_reco():
    return render_template("ml_reco.html")

@flask_app.route('/intents.html')
def intents_html():
    stored_intents_arr = get_intents_script.get_intent_fun(stored_intents_url)
    
    items = stored_intents_arr[0].items()
    keys = [key for key, value in items]
    headings = tuple(keys)
    data = ()
    for intent in stored_intents_arr:
        values = list(intent.values())
        tup = tuple(values)
        data += (tup,)
    return render_template("intents.html", headings=headings,
                           data=data)

@flask_app.route('/qos_intents.html')
def qos_intents_html():
    stored_qos_intents_arr = get_intents_script.get_intent_fun(stored_qos_intents_url)

    if len(stored_qos_intents_arr) > 0:
        items = stored_qos_intents_arr[0].items()
    else:
        items = dict(id=0, intent_type='', name='', value=0.0,
                                    host='', qos_intent_id='').items()
    keys = [key for key, value in items]
    headings = tuple(keys)
    data = ()
    for intent in stored_qos_intents_arr:
        values = list(intent.values())
        tup = tuple(values)
        data += (tup,)
    return render_template("qos_intents.html", headings=headings,
                           data=data)

@flask_app.route('/', methods =["GET", "POST"])
def intent_html():
    stored_qos_intents_arr = get_intents_script.get_intent_fun(stored_qos_intents_url)
    intents_ids = []
    for intent in stored_qos_intents_arr:
        intents_ids.append(intent['qos_intent_id'])
    #print('intents ids: ', intents_ids)
    #global intent
    if request.method == "POST":
        import extract_command
        #intent = request.form.get("intent")
        intent = request.get_data(as_text=True)[7:]
        intent = intent.replace("+", " ")
        intent = extract_command.extract_command_fun(intent)
        #print('extracted intent: ', intent)
        if intent['command'] == 'delete_intent':
            intent_presence = 0
            for i in range(len(intents_ids)):
                if intents_ids[i] == intent['qos_intent_id']:
                    intent_presence = 1
            if intent_presence == 0:
                return render_template('index.html', output_text='Incorrect QOS Intent ID. QOS Intent not found')
            else:
                return render_template('index.html', output_text='The command entered: {}'.format(intent))
        else:
            return render_template('index.html', output_text='The command entered: {}'.format(intent))


app.mount("/gui", WSGIMiddleware(flask_app))
static_directory = config.static_directory
app.mount("/static", StaticFiles(directory=static_directory), name="static")

def task():
    #uvicorn_url = 'http://' + host + ':' + port
    #print('App hosted on ', uvicorn_url)
    #uvicorn.run("main:app", host=host, port=int(port), reload=True, log_level='critical')
    uvicorn.run("main:app", host=host, port=int(port), reload=True)


def sched():
    run_whatif_loop.run_whatif_loop_fun()


if __name__ == "__main__":
    p1 = Process(target = task)
    p2 = Process(target = sched)
    p1.start()
    p2.start()
    p1.join()
    p2.join()



