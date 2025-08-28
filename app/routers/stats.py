from fastapi import  APIRouter, Request
from utils.log_config import setup_logging

logger = setup_logging(__name__)
router = APIRouter()

"""
    REST endpoints for the stats
"""

@router.get("/stats/intents")
def get_intents(request: Request):
    return {"intents": []}


@router.get("/stats/threats")
def get_threats(request: Request):
    return {"threats": []}


@router.get("/stats/threat-status")
def get_threat_status(request: Request):
    return {"threat_status": {"" : ""}}


@router.get("/stats/hosts")
def get_hosts(request: Request):
    return {"hosts": []}


@router.get("/stats/mitigations")
def get_mitigations(request: Request):
    return {"mitigations": []}

