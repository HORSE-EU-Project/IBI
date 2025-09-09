"""
    Definition of constants
"""

class Const:

    # Types of environment
    APP_ENV_DEV = "development"
    APP_ENV_PROD = "production"
    
    # Application
    APP_NAME = "HORSE-IBI"
    APP_VERSION = "0.0.3a"
    APP_ENV = APP_ENV_DEV

    # Server related
    APP_HOST = "0.0.0.0"
    APP_PORT = 8001

    # Intent processing loop
    THREAD_INTENT_WAIT = 5.0
    THREAT_TIMEOUT = 2.0 * 60.0  # 2 minutes

    # Digital Twin related constants
    IADT_PPS_THRESHOLD = 0.5

    # CAS related constants (parameter tuning)
    CAS_RATE_LIMITTING_INCREMENT = 1


