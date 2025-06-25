import logging
from fastapi import APIRouter
from models import SecurityIntent

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/intents")
async def get_intents():
    return {"ping": "pong"}


@router.post("/intents", status_code=201)
def post_intent(intent: SecurityIntent):
    logger.debug(f"Received intent: {intent}")
    return intent

@router.put("/intents")
def put_intent(intent: SecurityIntent):
    logger.debug(f"Updating intent: {intent}")
    return intent