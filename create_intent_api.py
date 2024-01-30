from fastapi import FastAPI
from pydantic import BaseModel, Field
import uvicorn
import sys

#CREATE THE API FIRST
app = FastAPI()

print('creating intent api')
host = sys.argv[1]
#host = "192.168.56.1"
port = 7777
class Intent(BaseModel):
    intent_type: str
    threat: str
    host: list
    time_frame: str

intents = [Intent(intent_type='', threat='', host=[], time_frame='')]

@app.get("/intents")
async def get_intents():
    return intents

@app.post("/intents", status_code=201)
async def add_intent(intent: Intent):
    intents.append(intent)
    return intent

@app.put("/intents")
async def replace_intent(intent: Intent):
    intents.clear()
    intents.append(intent)
    return intent


if __name__ == "__main__":
   uvicorn.run("create_intent_api:app", host=host, port=port, reload=True)