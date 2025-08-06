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


class DTEIntent(BaseModel):
    intent_type: DTEIntentType
    threat: str
    host: list
    duration: int