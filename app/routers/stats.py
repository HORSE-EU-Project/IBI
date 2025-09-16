from fastapi import APIRouter, Request
from pydantic_core import TzInfo
from utils.log_config import setup_logging
from typing import List, Dict, Any
from data.store import InMemoryStore
from datetime import datetime, timezone
from models.core_models import DetectedThreat
logger = setup_logging(__name__)
router = APIRouter()

"""
    REST endpoints for the stats
"""

@router.get("/stats/intents")
def get_intents(request: Request):
    """Get all intents with their status"""
    store = InMemoryStore()
    intents = store.intent_get_all()
    intents_list = []
    for intent in intents:
        intents_list.append({
            "id": intent.uid[-5:],
            "description": intent.description,
            "status": "fulfilled" if intent.fulfilled else "not-fulfilled",
            "created_at": (
                datetime.fromtimestamp(intent.start_time, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if intent.start_time is not None else None
            ),
            "updated_at": (
                datetime.fromtimestamp(intent.end_time, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if intent.end_time is not None else None
            ),
            "uid": intent.uid
        })
    return {"intents": intents_list}


@router.get("/stats/intents-summary")
def get_intents_summary(request: Request):
    """Get intents summary counts"""
    store = InMemoryStore()
    intents = store.intent_get_all()
    fulfilled = len([intent for intent in intents if intent.fulfilled])
    not_fulfilled = len([intent for intent in intents if not intent.fulfilled])
    total = len(intents)
    return {
        "fulfilled": fulfilled,
        "not_fulfilled": not_fulfilled,
        "total": total
    }


@router.get("/stats/threats")
def get_threats(request: Request):
    """Get all threats with their status"""
    store = InMemoryStore()
    threats = store.threat_get_all()
    threats_list = []
    for threat in threats:
        status = threat.status.value.lower()
        threats_list.append({
            "id": threat.uid[-5:],
            "name": threat.threat_name,
            "type": threat.threat_type,
            "status": status,
            "hosts": threat.hosts,
            "reported_at": (
                datetime.fromtimestamp(threat.start_time, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if threat.start_time is not None else None
            ),
            "last_update": (
                datetime.fromtimestamp(threat.last_update, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if threat.last_update is not None else None
            )
        })
    return {"threats": threats_list}


@router.get("/stats/threat-status")
def get_threat_status(request: Request):
    """Get threat status summary counts"""
    store = InMemoryStore()
    threats = store.threat_get_all()
    new = len([threat for threat in threats if threat.status == DetectedThreat.ThreatStatus.NEW])
    under_emulation = len([threat for threat in threats if threat.status == DetectedThreat.ThreatStatus.UNDER_EMULATION])
    under_mitigation = len([threat for threat in threats if threat.status == DetectedThreat.ThreatStatus.UNDER_MITIGATION])
    reincident = len([threat for threat in threats if threat.status == DetectedThreat.ThreatStatus.REINCIDENT])
    mitigated = len([threat for threat in threats if threat.status == DetectedThreat.ThreatStatus.MITIGATED])
    total = len(threats)
    return {
        "new": new,
        "under_emulation": under_emulation,
        "under_mitigation": under_mitigation,
        "reincident": reincident,
        "mitigated": mitigated,
        "total": total
    }


@router.get("/stats/mitigations")
def get_mitigations(request: Request):
    """Get all mitigation actions"""
    store = InMemoryStore()
    mitigations = store.mitigation_get_all()
    mitigations_list = []
    for mitigation in mitigations:
        mitigations_list.append({
            "id": mitigation.uid[-5:],
            "name": mitigation.name,
            "category": mitigation.category.value,
            "threats": mitigation.threats if len(mitigation.threats) == 1 else ", ".join(mitigation.threats),
            "priority": mitigation.priority,
            "enabled": mitigation.enabled,
        })
    return {"mitigations": mitigations_list}


@router.get("/stats/ndt")
def get_ndt_queue(request: Request):
    """Get stats about IA-NDT queue"""
    store = InMemoryStore()
    ndt_queue_size = 0
    for job in store._dt_jobs:
        if job.kpi_before is None:
            ndt_queue_size =+1
        if job.kpi_after is None:
            ndt_queue_size=+1
            
    ndt_status = "available" if store._dt_available else "busy"
    return {"queue_size": ndt_queue_size, "ndt_status": ndt_status}


@router.get("/stats/ibi")
def get_ibi_status(request: Request):
    """Return General Status of the IBI"""
    store = InMemoryStore()
    status = "running" if not store._ibi_compromised else "stopped"
    return {"status": status}


"""
Used only for testing purposes
"""
@router.post("/stats/ibi-test")
def set_ibi_status(request: Request):
    """Set the IBI status to compromised"""
    store = InMemoryStore()
    store._ibi_compromised = not store._ibi_compromised
    return {"status": "ok"}