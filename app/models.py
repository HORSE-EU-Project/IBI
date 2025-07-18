from pydantic import BaseModel
from enum import Enum
"""
Data models used in the application
"""

"""
Intent related models
"""
class IntentType(str, Enum):
    MITIGATION = "mitigation"
    PREVENTION = "prevention"


class SecurityIntent(BaseModel):
    intent_type: IntentType
    threat: str
    host: list
    duration: int


# class QoSIntentType(str, Enum):
#     QOS_NTP = "qos_ntp"
#     QOS_DNS = "qos_dns"
#     QOS_PFCP = "qos_pfcp"


# class QoSMetricName(str, Enum):
#     RELIABILITY = "reliability"
#     BANDWIDTH = "bandwidth"
#     LATENCY = "latency"


# class QoSIntent(BaseModel):
#     intent_type: QoSIntentType
#     name: QoSMetricName
#     value: float
#     unit: str
#     host: list
