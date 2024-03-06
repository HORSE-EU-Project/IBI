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
import config
import get_intents_script


warnings.filterwarnings('ignore')

parameters = config.parameters
host = config.host
port = config.port
intents_url = config.intents_url
stored_intents_url = config.stored_intents_url

#clears the existing intent store if you chose that in the config file
if parameters['clear_intent_store'] == 'true':
    empty_intent_store.empty_fun()
    print('cleared')

templates_directory = config.templates_directory
#flask app
flask_app = Flask(__name__,template_folder=templates_directory)

#fastAPI app
app = FastAPI()

#CREATE THE APIs FIRST
print('creating APIs')

@app.get('/')
def first_page():
    to_return = {
        'gui_endpoint': '/gui',
    }
    return to_return

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
    whatif_loop.whatif_receive_fun(whatif_receive)
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

@flask_app.route('/', methods =["GET", "POST"])
def intent_html():
    if request.method == "POST":
        import extract_command
        intent = request.get_data(as_text=True)[7:]
        intent = intent.replace("+", " ")
        intent = extract_command.extract_command_fun(intent)
        return render_template('index.html', output_text='The command entered: {}'.format(intent))


app.mount("/gui", WSGIMiddleware(flask_app))
static_directory = config.static_directory
app.mount("/static", StaticFiles(directory=static_directory), name="static")

def task():
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



