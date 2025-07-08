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

    # Intent status
    INTENT_STATUS_NEW = "new"
    INTENT_STATUS_IN_PROGRESS = "in_progress"
    INTENT_STATUS_RENEWED = "renewed"
    INTENT_STATUS_UNDER_MITIGATION = "under_mitigation"
    INTENT_STATUS_MITIGATED = "mitigated"

    # Intent processing loop
    THREAD_INTENT_WAIT = 1.0

    # Elasticsearch indexes
    INTENTS_INDEX = "intents"
    MITIGATION_INDEX = "mitigations"

