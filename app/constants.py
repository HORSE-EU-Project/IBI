"""
    Definition of constants
"""

class Const:
    # Application
    APP_NAME = "HORSE-IBI"
    APP_VERSION = "0.0.3a"

    # Server related
    APP_HOST = "0.0.0.0"
    APP_PORT = 8000

    # Intent processing loop
    THREAD_INTENT_WAIT = 5.0
    THREAT_TIMEOUT = 2.0 * 60.0  # 2 minutes

    # Elasticsearch indexes
    INTENTS_INDEX = "intents"
    MITIGATION_INDEX = "mitigations"
    ASSOCIATIONS_INDEX = "associations"

    # Digital Twin related constants
    IADT_PPS_THRESHOLD = 0.5

    # CAS related constants (parameter tuning)
    CAS_RATE_MITITING_INCREMENT = 1


