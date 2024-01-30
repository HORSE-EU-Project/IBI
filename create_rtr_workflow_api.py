from fastapi import FastAPI
from pydantic import BaseModel, Field
import uvicorn
import sys

#CREATE THE API FIRST
app = FastAPI()

print('creating workflow api')
host = sys.argv[1]
#host = "192.168.56.1"
port = 7778

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
async def get_workflow():
    return workflows

@app.post("/workflows", status_code=201)
async def add_workflow(workflow: Workflow):
    workflows.append(workflow)
    return workflow

@app.put("/workflows")
async def replace_workflow(workflow: Workflow):
    workflows.clear()
    workflows.append(workflow)
    return workflow



if __name__ == "__main__":
   uvicorn.run("create_rtr_workflow_api:app", host=host, port=port, reload=True)