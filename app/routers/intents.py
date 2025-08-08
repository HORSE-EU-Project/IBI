import logging
from fastapi import APIRouter, Response
from models.api_models import DTEIntent
from controllers.dte_controller import DTEController

logger = logging.getLogger(__name__)
router = APIRouter()
controller = DTEController()


@router.get("/intents")
def get_intents():
    logger.debug("Fetching all intents")
    intents = controller.get_all_intents()
    return {"intents": intents}


@router.post("/intents", status_code=201)
def post_intent(dte_intent: DTEIntent, response:Response):
    logger.debug(f"Received intent: {dte_intent}")
    status = controller.process_dte_intent(dte_intent)
    if status == DTEController.RETURN_STATUS_CREATED:
        logger.info(f"Intent {dte_intent} created successfully")
        response.status_code = 201
        return {"created": dte_intent}
    elif status == DTEController.RETURN_STATUS_UPDATED:
        logger.info(f"Intent or system state updated successfully")
        response.status_code = 208
        return {"info": "Intent or system state updated"}
    else:
        logger.error(f"Failed to create intent {dte_intent}")
        response.status_code = 500
        return {"error": "Failed to create intent"}


@router.put("/intents")
def put_intent(dte_intent: DTEIntent):
    logger.debug(f"Redirecting to post_intent for intent: {dte_intent}")
    post_intent(dte_intent)