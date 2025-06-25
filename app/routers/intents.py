from fastapi import APIRouter

router = APIRouter()

@router.get("/intents")
async def get_intents():
    return {"ping": "pong"}


@router.post("/intents", status_code=201)
def post_intents(intent: Intent):
    # intents.append(intent)
    #execute_qos()
    return intent

@router.put("/intents")
def put_intents(intent: Intent):
    intents.clear()
    intents.append(intent)
    #calls the intent manager function
    intent.duration = str(intent.duration)
    #execute_qos()
    intent_manager.execute_intent_manager(intent)
    return intent