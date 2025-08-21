from fastapi import APIRouter, HTTPException
from utils.log_config import setup_logging
from models.api_models import ImpactAnalysisRequest
from controllers.iandt_controller import IANDTController

# Configure logging
logger = setup_logging(__name__)

router = APIRouter()

@router.post("/impact-analysis")
async def process_impact_analysis(request: ImpactAnalysisRequest):
    """
    Process asyncronous answer from the IA-NDT. The answer is a JSON o document.
    The digital twin can answer with two different scenarios: a result form a measurement without
    a mitigation action (monitor) or a result from a measurement with a mitigation action applied.
    1. Send the answer to the ID-NDT controller to the processed
        1. if the answer is a result from a measurement without a mitigation action applied, 
            it should update the kpi_before field of the DTJob object in the app.store 
            _dt_jobs list wich has the same id as the request.id field.
        2. if the answer is a result from a measurement with a mitigation action applied, it 
            should update the kpi_after field of the DTJob object in the app.store _dt_jobs 
            list wich has the same id as the request.id field.
    Ther is not a clear way to identify whether the answer is from a measurement without a 
    mitigation action, therefore the IBN module should infer the type of answer according to 
    the internal state of the simulation. Basically, if the DTJob object has a kpi_before field 
    with the 'None' value, it means that the answer is from a measurement without a mitigation 
    action applied. If the kpi_before field has a value, it means that the answer is from a 
    measurement with a mitigation action applied.
    """
    try:

        data = request.model_dump()
        # Extract id and value from the request JSON
        job_id = request.id
        value = float(data["what"]["KPIs"]["result"]["value"])
        # Import and call the controller function
        iandt_controller = IANDTController()
        iandt_controller.process_response(job_id, value)
        return {"status": "success", "job_id": job_id, "value": value}

    except (KeyError, TypeError, ValueError) as e:
        logger.error(f"Failed to extract KPI value: {e}")
        raise HTTPException(status_code=400, detail="Malformed KPI result in request")
    except ValueError as e:
        logger.error(f"Invalid value format: {e}")
        raise HTTPException(status_code=400, detail="Invalid value format")
    except Exception as e:
        logger.error(f"Error processing impact analysis: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")