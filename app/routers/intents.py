import logging
from fastapi import APIRouter, Response
from models import SecurityIntent
from intent_manager import IntentManager

logger = logging.getLogger(__name__)
router = APIRouter()
intent_manager = IntentManager()

@router.get("/intents")
async def get_intents():
    return {"ping": "pong"}


@router.post("/intents", status_code=201)
def post_intent(intent: SecurityIntent, response:Response):
    logger.debug(f"Received intent: {intent}")
    status = intent_manager.process_intent_request(intent)
    if status == IntentManager.INTENT_CREATED:
        logger.info(f"Intent {intent} created successfully")
        response.status_code = 201 
    elif status == IntentManager.INTENT_ALREADY_EXISTS:
        logger.warning(f"Intent {intent} already exists")
        response.status_code = 208
        return intent
    else:
        logger.error(f"Failed to create intent {intent}")
        response.status_code = 500
        return {"error": "Failed to create intent"}


@router.put("/intents")
def put_intent(intent: SecurityIntent):
    logger.debug(f"Redirecting to post_intent for intent: {intent}")
    post_intent(intent)