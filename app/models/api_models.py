from pydantic import BaseModel
from enum import Enum
"""
Data models used in the application
"""

"""
Intent related models
"""
class DTEIntentType(str, Enum):
    MITIGATION = "mitigation"
    PREVENTION = "prevention"
    DETECTION = "detection"


class DTEIntent(BaseModel):
    intent_type: DTEIntentType
    threat: str
    host: list
    duration: int

    def __str__(self) -> str:
        return f"DTEIntent(intent_type={self.intent_type.value}, threat={self.threat}, host={self.host}, duration={self.duration})"

"""
IANDT related models
"""
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



ResultModel, ElementModel, KPIsModel, WhatModel, ImpactAnalysisRequest