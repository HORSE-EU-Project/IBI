from dataclasses import field
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import uuid4
from .api_models import DTEIntent

class Expectation:
    name: str
    value: str

    def __init__(self, name: str, value: str):
        self.name = name
        self.value = value


class CoreIntent:
    uid: str = field(default_factory=lambda: str(uuid4()))
    intent_type: str
    threat: str
    host: List[str]
    duration: int
    start_time: Optional[int] = None
    end_time: Optional[int] = None
    expectations: List[Expectation] = field(default_factory=list)
    satisfied: bool = False
    
    def __init__(self, dte_intent: DTEIntent):
        
        # Import from DTE Intent
        self.intent_type = dte_intent.intent_type
        self.threat = dte_intent.threat
        self.host = dte_intent.host
        self.duration = dte_intent.duration
        self.start_time = int(datetime.now().timestamp())
        self.end_time = self.start_time + self.duration

    def get_uid(self) -> str:
        return self.uid

    def timedout(self) -> bool:
        """
        Check if the intent has timed out.
        """
        return datetime.now().timestamp() > self.end_time