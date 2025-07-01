import logging
from fastapi import APIRouter
from models import SecurityIntent
from intent_manager import IntentManager

logger = logging.getLogger(__name__)
router = APIRouter()
intent_manager = IntentManager()

@router.get("/intents")
async def get_intents():
    return {"ping": "pong"}


@router.post("/intents", status_code=201)
def post_intent(intent: SecurityIntent):
    logger.debug(f"Received intent: {intent}")
    intent_manager.add(intent)
    return intent


@router.put("/intents")
def put_intent(intent: SecurityIntent):
    logger.debug(f"Updating intent: {intent}")
    return intent