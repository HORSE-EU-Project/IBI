import logging
from fastapi import APIRouter, Response
from models.api_models import DTEIntent
from controllers.dte_controller import DTEController

logger = logging.getLogger(__name__)
router = APIRouter()
intent_manager = DTEController()

@router.post("/intents", status_code=201)
def post_intent(dte_intent: DTEIntent, response:Response):
    logger.debug(f"Received intent: {dte_intent}")
    status = intent_manager.process_dte_intent(dte_intent)
    if status == DTEController.RETURN_STATUS_CREATED:
        logger.info(f"Intent {dte_intent} created successfully")
        response.status_code = 201
    elif status == DTEController.RETURN_STATUS_UPDATED:
        logger.warning(f"Intent {dte_intent} already exists. Updating threat state")
        response.status_code = 208
        return dte_intent
    else:
        logger.error(f"Failed to create intent {dte_intent}")
        response.status_code = 500
        return {"error": "Failed to create intent"}


@router.put("/intents")
def put_intent(dte_intent: DTEIntent):
    logger.debug(f"Redirecting to post_intent for intent: {dte_intent}")
    post_intent(dte_intent)