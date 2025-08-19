from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from utils.log_config import setup_logging
from integrations.iandt import ImpactAnalysisDT

from constants import Const

# Configure logging
logger = setup_logging(__name__)

router = APIRouter()

# Define the request models
class ResultModel(BaseModel):
    value: str
    unit: str

class ElementModel(BaseModel):
    node: str
    interface: str

class KPIsModel(BaseModel):
    element: ElementModel
    metric: str
    result: ResultModel

class WhatModel(BaseModel):
    KPIs: KPIsModel

class ImpactAnalysisRequest(BaseModel):
    id: str
    topology_name: str
    attack: str
    what: WhatModel

@router.post("/impact-analysis")
async def process_impact_analysis(request: ImpactAnalysisRequest):
    """
    Process impact analysis data and trigger external integration.
    """
    try:
        # Create instance of ImpactAnalysisDT
        impact_analysis = ImpactAnalysisDT()
        
        # Convert request to dict for processing
        request_dict = request.dict()
        
        # Call the method to print the received answer
        impact_analysis.log_received_answer(request_dict)
        
        # Check if value is below threshold
        value = float(request.what.KPIs.result.value)
        # TODO: Update logic to handle IAND responses
        return
        if value < Const.IADT_PPS_THRESHOLD:
            logger.warning(
                f"Impact analysis value {value} is below threshold {Const.IADT_PPS_THRESHOLD}. "
                f"Node: {request.what.KPIs.element.node}, "
                f"Interface: {request.what.KPIs.element.interface}, "
                f"Metric: {request.what.KPIs.metric}"
            )
        else:
            logger.info(
                f"Impact analysis value {value} is above threshold {Const.IADT_PPS_THRESHOLD}. "
                f"Node: {request.what.KPIs.element.node}, "
                f"Interface: {request.what.KPIs.element.interface}, "
                f"Metric: {request.what.KPIs.metric}"
            )
            logger.info("Impact analysis completed. Updating intent status. ID: %s", request.id)
            impact_analysis.update_intent_status(
                request.id, 
                Const.INTENT_STATUS_NDT_VALIDATED
            )
        return {
            "status": "success",
            "message": "Answer of the simulation received",
            "id": request.id
        }
        
    except ValueError as e:
        logger.error(f"Invalid value format: {e}")
        raise HTTPException(status_code=400, detail="Invalid value format")
    except Exception as e:
        logger.error(f"Error processing impact analysis: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")