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
    THREAT_TIMEOUT = 30 # 2.0 * 60.0  # 2 minutes

    # Elasticsearch indexes
    INTENTS_INDEX = "intents"
    MITIGATION_INDEX = "mitigations"
    ASSOCIATIONS_INDEX = "associations"

    IADT_PPS_THRESHOLD = 2.0

