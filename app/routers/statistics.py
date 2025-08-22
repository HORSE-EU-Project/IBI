from fastapi import APIRouter
from typing import Dict, List, Any
from data.store import InMemoryStore
from models.core_models import CoreIntent, DetectedThreat, MitigationAction
from utils.log_config import setup_logging

logger = setup_logging(__name__)
router = APIRouter()
store = InMemoryStore()


@router.get("/statistics/overview")
def get_statistics_overview():
    """
    Get a general overview of the IBI system statistics.
    Returns summary counts of intents, threats, and mitigations.
    """
    logger.debug("Fetching statistics overview")
    
    try:
        # Get all data from store
        intents = store.intent_get_all()
        threats = store.threat_get_all()
        mitigations = store.mitigation_get_all()
        
        # Count intents by status
        active_intents = sum(1 for intent in intents if not intent.timedout())
        expired_intents = sum(1 for intent in intents if intent.timedout())
        satisfied_intents = sum(1 for intent in intents if intent.satisfied)
        
        # Count threats by status
        threat_status_counts = {}
        for status in DetectedThreat.ThreatStatus:
            threat_status_counts[status.value] = sum(
                1 for threat in threats if threat.status == status
            )
        
        # Count mitigations by category
        mitigation_category_counts = {}
        for category in MitigationAction.MitigationCategory:
            mitigation_category_counts[category.value] = sum(
                1 for mitigation in mitigations if mitigation.category == category
            )
        
        # Count enabled vs disabled mitigations
        enabled_mitigations = sum(1 for mitigation in mitigations if mitigation.enabled)
        disabled_mitigations = sum(1 for mitigation in mitigations if not mitigation.enabled)
        
        overview = {
            "intents": {
                "total": len(intents),
                "active": active_intents,
                "expired": expired_intents,
                "satisfied": satisfied_intents
            },
            "threats": {
                "total": len(threats),
                "by_status": threat_status_counts
            },
            "mitigations": {
                "total": len(mitigations),
                "enabled": enabled_mitigations,
                "disabled": disabled_mitigations,
                "by_category": mitigation_category_counts
            }
        }
        
        logger.info(f"Statistics overview generated: {overview}")
        return overview
        
    except Exception as e:
        logger.error(f"Error generating statistics overview: {e}")
        return {"error": "Failed to generate statistics overview"}


@router.get("/statistics/intents")
def get_intents_statistics():
    """
    Get detailed statistics about all intents with their status.
    """
    logger.debug("Fetching intents statistics")
    
    try:
        intents = store.intent_get_all()
        
        intents_data = []
        for intent in intents:
            intent_info = {
                "uid": intent.uid,
                "intent_type": intent.intent_type,
                "threat": intent.threat,
                "host": intent.host,
                "duration": intent.duration,
                "start_time": intent.start_time,
                "end_time": intent.end_time,
                "satisfied": intent.satisfied,
                "timedout": intent.timedout(),
                "status": "active" if not intent.timedout() else "expired"
            }
            intents_data.append(intent_info)
        
        # Group by intent type
        intents_by_type = {}
        for intent in intents_data:
            intent_type = intent["intent_type"]
            if intent_type not in intents_by_type:
                intents_by_type[intent_type] = []
            intents_by_type[intent_type].append(intent)
        
        # Group by threat
        intents_by_threat = {}
        for intent in intents_data:
            threat = intent["threat"]
            if threat not in intents_by_threat:
                intents_by_threat[threat] = []
            intents_by_threat[threat].append(intent)
        
        statistics = {
            "total_intents": len(intents_data),
            "intents": intents_data,
            "grouped_by_type": intents_by_type,
            "grouped_by_threat": intents_by_threat
        }
        
        logger.info(f"Intents statistics generated for {len(intents_data)} intents")
        return statistics
        
    except Exception as e:
        logger.error(f"Error generating intents statistics: {e}")
        return {"error": "Failed to generate intents statistics"}


@router.get("/statistics/threats")
def get_threats_statistics():
    """
    Get detailed statistics about all threats with their status.
    """
    logger.debug("Fetching threats statistics")
    
    try:
        threats = store.threat_get_all()
        
        threats_data = []
        for threat in threats:
            threat_info = {
                "uid": threat.uid,
                "threat_type": threat.threat_type,
                "threat_name": threat.threat_name,
                "hosts": threat.hosts,
                "start_time": threat.start_time,
                "end_time": threat.end_time,
                "last_update": threat.last_update,
                "status": threat.status.value,
                "expired": threat.is_expired()
            }
            threats_data.append(threat_info)
        
        # Group by threat type
        threats_by_type = {}
        for threat in threats_data:
            threat_type = threat["threat_type"]
            if threat_type not in threats_by_type:
                threats_by_type[threat_type] = []
            threats_by_type[threat_type].append(threat)
        
        # Group by threat name
        threats_by_name = {}
        for threat in threats_data:
            threat_name = threat["threat_name"]
            if threat_name not in threats_by_name:
                threats_by_name[threat_name] = []
            threats_by_name[threat_name].append(threat)
        
        # Group by status
        threats_by_status = {}
        for threat in threats_data:
            status = threat["status"]
            if status not in threats_by_status:
                threats_by_status[status] = []
            threats_by_status[status].append(threat)
        
        statistics = {
            "total_threats": len(threats_data),
            "threats": threats_data,
            "grouped_by_type": threats_by_type,
            "grouped_by_name": threats_by_name,
            "grouped_by_status": threats_by_status
        }
        
        logger.info(f"Threats statistics generated for {len(threats_data)} threats")
        return statistics
        
    except Exception as e:
        logger.error(f"Error generating threats statistics: {e}")
        return {"error": "Failed to generate threats statistics"}


@router.get("/statistics/mitigations")
def get_mitigations_statistics():
    """
    Get detailed statistics about all mitigation actions.
    """
    logger.debug("Fetching mitigations statistics")
    
    try:
        mitigations = store.mitigation_get_all()
        
        mitigations_data = []
        for mitigation in mitigations:
            mitigation_info = {
                "uid": mitigation.uid,
                "name": mitigation.name,
                "category": mitigation.category.value,
                "threats": mitigation.threats,
                "fields": mitigation.fields,
                "priority": mitigation.priority,
                "enabled": mitigation.enabled,
                "parameters": mitigation.parameters
            }
            mitigations_data.append(mitigation_info)
        
        # Group by category
        mitigations_by_category = {}
        for mitigation in mitigations_data:
            category = mitigation["category"]
            if category not in mitigations_by_category:
                mitigations_by_category[category] = []
            mitigations_by_category[category].append(mitigation)
        
        # Group by enabled status
        enabled_mitigations = [m for m in mitigations_data if m["enabled"]]
        disabled_mitigations = [m for m in mitigations_data if not m["enabled"]]
        
        # Group by priority
        mitigations_by_priority = {}
        for mitigation in mitigations_data:
            priority = mitigation["priority"]
            if priority not in mitigations_by_priority:
                mitigations_by_priority[priority] = []
            mitigations_by_priority[priority].append(mitigation)
        
        statistics = {
            "total_mitigations": len(mitigations_data),
            "mitigations": mitigations_data,
            "grouped_by_category": mitigations_by_category,
            "enabled": enabled_mitigations,
            "disabled": disabled_mitigations,
            "grouped_by_priority": mitigations_by_priority
        }
        
        logger.info(f"Mitigations statistics generated for {len(mitigations_data)} mitigations")
        return statistics
        
    except Exception as e:
        logger.error(f"Error generating mitigations statistics: {e}")
        return {"error": "Failed to generate mitigations statistics"}


@router.get("/statistics/associations")
def get_associations_statistics():
    """
    Get statistics about associations between threats and mitigation actions.
    """
    logger.debug("Fetching associations statistics")
    
    try:
        threats = store.threat_get_all()
        
        associations_data = []
        for threat in threats:
            threat_associations = store.association_get(threat.uid)
            if threat_associations:
                association_info = {
                    "threat_uid": threat.uid,
                    "threat_type": threat.threat_type,
                    "threat_name": threat.threat_name,
                    "threat_status": threat.status.value,
                    "mitigations": [
                        {
                            "uid": mitigation.uid,
                            "name": mitigation.name,
                            "category": mitigation.category.value
                        }
                        for mitigation in threat_associations
                    ],
                    "mitigation_count": len(threat_associations)
                }
                associations_data.append(association_info)
        
        # Count associations by threat type
        associations_by_threat_type = {}
        for association in associations_data:
            threat_type = association["threat_type"]
            if threat_type not in associations_by_threat_type:
                associations_by_threat_type[threat_type] = []
            associations_by_threat_type[threat_type].append(association)
        
        # Count associations by mitigation category
        associations_by_category = {}
        for association in associations_data:
            for mitigation in association["mitigations"]:
                category = mitigation["category"]
                if category not in associations_by_category:
                    associations_by_category[category] = 0
                associations_by_category[category] += 1
        
        statistics = {
            "total_associations": len(associations_data),
            "associations": associations_data,
            "grouped_by_threat_type": associations_by_threat_type,
            "mitigation_usage_by_category": associations_by_category
        }
        
        logger.info(f"Associations statistics generated for {len(associations_data)} associations")
        return statistics
        
    except Exception as e:
        logger.error(f"Error generating associations statistics: {e}")
        return {"error": "Failed to generate associations statistics"}
