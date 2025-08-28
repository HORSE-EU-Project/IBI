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
    description: str
    fulfilled: bool = False
    
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
        self.description = self._generate_description(dte_intent)

    def get_uid(self) -> str:
        return self.uid

    def timedout(self) -> bool:
        """
        Check if the intent has timed out.
        """
        return datetime.now().timestamp() > self.end_time

    def _generate_description(self, dte_intent: DTEIntent) -> str:
        """
        Generate a description for the intent.
        """
        # Generate a declarative description of the intent based on RFC9315 and the provided table.
        # The description should summarize the intent in a human-readable, declarative way.
        # Example: "Mitigate ddos_amplification on hosts ['host1'] for 600s using udp_traffic_filter"
        # If dte_intent has an 'action' attribute, include it; otherwise, omit.

        # Compose the main parts
        intent_type = getattr(dte_intent, "intent_type", "unknown")
        threat = getattr(dte_intent, "threat", "unknown")
        hosts = getattr(dte_intent, "host", [])
        duration = getattr(dte_intent, "duration", None)
        action = getattr(dte_intent, "action", None)
        # Try to get a friendly name for the intent type
        intent_type_str = str(intent_type).capitalize()
        threat_str = str(threat)
        hosts_str = f" on hosts {hosts}" if hosts else ""
        duration_str = f" for {duration}s" if duration else ""

        description = f"{intent_type_str} {threat_str}{hosts_str}{duration_str}".strip()
        return description

    def set_fulfilled(self, fulfilled: bool) -> None:
        """
        Set the satisfied status of the intent.
        """
        self.fulfilled = fulfilled
    

    def __repr__(self):
        return f"CoreIntent(uid={self.uid}, intent_type={self.intent_type}, threat={self.threat}, host={self.host}, duration={self.duration}, start_time={self.start_time}, end_time={self.end_time}, description={self.description}, satisfied={self.fulfilled})"
    

class DetectedThreat:
    """
    Represents a detected threat in the system.
    """

    class ThreatStatus(Enum):
        NEW = "NEW"
        UNDER_EMULATION = "UNDER_EMULATION"
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
        # Do not reopen a threat that is already mitigated
        if self.status == self.ThreatStatus.MITIGATED:
            return
        # Only update the status to REINCIDENT if the threat is UNDER_MITIGATION
        if self.status == self.ThreatStatus.UNDER_MITIGATION:
            self.status = self.ThreatStatus.REINCIDENT
        # Always update the last update time (extend the timeout)
        self.last_update = int(datetime.now().timestamp())


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
    parameters: Dict[str, Any] = {}

    def __init__(self, name, category, threats, fields):
        self.uid = str(uuid4())
        self.name = name
        self.category = MitigationAction.MitigationCategory(category)
        self.threats = threats
        self.fields = fields
        self.priority = 0
        self.enabled = True

    def define_field(self, field_name: str, field_value: Any) -> None:
        """
        Define a field for the mitigation action.
        
        :param field_name: Name of the field
        :param field_value: Value of the field
        """
        self.parameters[field_name] = field_value

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
    

class DTJob:
    """
    Represents a job in the Digital Twin.
    It keeps track of the threat and the mitigation action being emulated
    resulting measurements of applying the mitigation action.
    """

    class JobStatus(Enum):
        PENDING = "PENDING"
        COMPLETED = "COMPLETED"

    uid: str
    threat_id: str
    mitigation_id: str
    mitigation_obj: MitigationAction = None
    kpi_before: Optional[int] = None  # KPI before the mitigation action
    kpi_after: Optional[int] = None  # KPI after the mitigation action
    status: JobStatus = None

    def __init__(self, thread_id: str, migitation_id: str):
        self.uid = str(uuid4())
        self.threat_id = thread_id
        self.mitigation_id = migitation_id
        self.status = DTJob.JobStatus.PENDING

    def set_mitigation_obj(self, mitigation_obj: MitigationAction) -> None:
        """
        Set the mitigation object for the job.
        """
        self.mitigation_obj = mitigation_obj

    def update_kpi_before(self, kpi: int) -> None:
        """
        Update the KPI before applying the mitigation action.
        
        :param kpi: KPI value before the mitigation action
        """
        self.kpi_before = kpi

    def update_kpi_after(self, kpi: int) -> None:
        """
        Update the KPI after applying the mitigation action.
        
        :param kpi: KPI value after the mitigation action
        """
        self.kpi_after = kpi
        
    def update_status(self, status: JobStatus) -> None:
        """
        Update the status of the job.
        """
        self.status = status

    def __str__(self):
        return f"DTJob(uid={self.uid}, threat_id={self.threat_id}, mitigation_id={self.mitigation_id}, kpi_before={self.kpi_before}, kpi_after={self.kpi_after}, status={self.status})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "uid": self.uid,
            "threat_id": self.threat_id,
            "mitigation_id": self.mitigation_id,
            "kpi_before": self.kpi_before,
            "kpi_after": self.kpi_after,
            "status": self.status.value
        }