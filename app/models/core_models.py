from datetime import datetime
from typing import Optional, List
from uuid import uuid4

from app.constants import Const
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
        self.expectations = []

    def get_uid(self) -> str:
        return self.uid

    def timedout(self) -> bool:
        """
        Check if the intent has timed out.
        """
        return datetime.now().timestamp() > self.end_time
    

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
    host: List[str]
    start_time: Optional[int] = None
    update_time: Optional[int] = None
    end_time: Optional[int] = None
    status: ThreatStatus = ThreatStatus.NEW
    
    def __init__(self, dte_intent: DTEIntent):
        self.uid = str(uuid4())
        self.threat_type = dte_intent.intent_type
        for h in dte_intent.host:
            if h not in self.host:
                self.host.append(h)
        self.start_time = int(datetime.now().timestamp())
        self.update_time = self.start_time
        self.end_time = self.start_time + Const.THREAT_TIMEOUT

        

    def __repr__(self):
        return f"DetectedThreat(type={self.threat_type}, host={self.host}, timestamp={self.timestamp})"
    

class SystemState:
    """
    Represents the system state regarding threads.
    This is a placeholder for future implementation.
    """
    def __init__(self):
        self.state = {}

    def update_state(self, key: str, value: str):
        self.state[key] = value