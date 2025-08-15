import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import uuid4
from constants import Const
from .api_models import DTEIntent
from enum import Enum

class Expectation:
    name: str
    value: str

    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value


class CoreIntent:
    uid: str
    intent_type: str
    threat: str
    host: List[str]
    duration: int
    start_time: Optional[int] = None
    end_time: Optional[int] = None
    expectations: List[Expectation]
    satisfied: bool = False
    
    def __init__(self, dte_intent: DTEIntent):
        self.uid = str(uuid4())
        # Import from DTE Intent
        self.intent_type = dte_intent.intent_type
        self.threat = dte_intent.threat
        self.host = dte_intent.host
        self.duration = dte_intent.duration
        self.start_time = int(datetime.now().timestamp())
        self.end_time = self.start_time + self.duration
        # Initialize expectations
        self.expectations = []

    def get_uid(self) -> str:
        return self.uid

    def timedout(self) -> bool:
        """
        Check if the intent has timed out.
        """
        return datetime.now().timestamp() > self.end_time
    
    def __repr__(self):
        return f"CoreIntent(uid={self.uid}, intent_type={self.intent_type}, threat={self.threat}, host={self.host}, duration={self.duration}, start_time={self.start_time}, end_time={self.end_time}, expectations={self.expectations}, satisfied={self.satisfied})"
    

class DetectedThreat:
    """
    Represents a detected threat in the system.
    """

    class ThreatStatus(Enum):
        NEW = "NEW"
        UNDER_MITIGATION = "UNDER_MITIGATION"
        REINCIDENT = "REINCIDENT"
        MITIGATED = "MITIGATED"

    uid: str
    threat_type: str
    threat_name: str
    hosts: List[str]
    start_time: Optional[int] = None
    end_time: Optional[int] = None
    last_update: Optional[int] = None
    status: ThreatStatus = ThreatStatus.NEW
    
    def __init__(self, dte_intent: DTEIntent):
        self.uid = str(uuid4())
        self.threat_type = dte_intent.intent_type
        self.threat_name = dte_intent.threat
        self.hosts = dte_intent.host
        self.start_time = int(datetime.now().timestamp())
        self.end_time = self.start_time + Const.THREAT_TIMEOUT
        self.last_update = self.start_time


    def renew(self) -> None:
        """
        Renew the detected threat's timeout.
        """
        if self.status == self.ThreatStatus.MITIGATED:
            return
        self.last_update = int(datetime.now().timestamp())
        self.status = self.ThreatStatus.REINCIDENT


    def update_status(self, new_status: ThreatStatus):
        """
        Update the status of the detected threat.
        """
        self.status = new_status
        self.last_update = int(datetime.now().timestamp())


    def get_status(self) -> ThreatStatus:
        """
        Get the current status of the detected threat.
        """
        return self.status
    

    def is_expired(self) -> bool:
        """
        Check if the detected threat has expired.
        """
        return datetime.now().timestamp() > self.last_update + Const.THREAT_TIMEOUT

    def __repr__(self):
        return f"DetectedThreat(uid={self.uid}, threat_type={self.threat_type}, threat_name={self.threat_name}, hosts={self.hosts}, start_time={self.start_time}, end_time={self.end_time}, last_update={self.last_update}, status={self.status})"


class MitigationAction:
    """
    Represents a mitigation action that can be applied to handle threats.
    """

    class MitigationCategory(str, Enum):
        MITIGATION = "mitigation"
        PREVENTION = "prevention"
        DETECTION = "detection"

    uid: str
    name: str
    category: MitigationCategory
    threats: List[str]  # e.g., "dns_ddos", "ntp_ddos", etc.
    fields: List[str]
    priority: int = 0  # Lower number = higher priority
    enabled: bool = True

    def __init__(self, name, category, threats, fields):
        self.uid = str(uuid4())
        self.name = name
        self.category = MitigationAction.MitigationCategory(category)
        self.threats = threats
        self.fields = fields
        self.priority = 0
        self.enabled = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "uid": self.uid,
            "name": self.name,
            "category": self.category.value,
            "threats": self.threats,
            "fields": self.fields,
            "priority": self.priority,
            "enabled": self.enabled
        }

    def __repr__(self):
        return json.dumps(self.to_dict(), indent=4)