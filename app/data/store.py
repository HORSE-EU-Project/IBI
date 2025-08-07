from utils.log_config import setup_logging
from models.core_models import CoreIntent, DetectedThreat
import threading
from typing import Dict, List, Any, Optional


class InMemoryStore:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(InMemoryStore, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._data_lock = threading.RLock()
            self._core_intents: Dict[str, CoreIntent] = {}
            self._threats: Dict[str, DetectedThreat] = {}
            self._logger = setup_logging(__name__)
            self._initialized = True

    def intent_add(self, intent: CoreIntent) -> None:
        with self._data_lock:
            self._core_intents[intent.get_uid()] = intent
            self._logger.info(f"Intent added: {intent.get_uid()}")

    def intent_update(self, key: str, intent: CoreIntent) -> bool:
        with self._data_lock:
            if key in self._core_intents:
                self._core_intents[key] = intent
                self._logger.info(f"Intent updated: {key}")
                return True
            return False

    def intent_get(self, key: str) -> Optional[CoreIntent]:
        with self._data_lock:
            return self._core_intents.get(key)

    def intent_remove(self, key: str) -> bool:
        with self._data_lock:
            self._logger.info(f"Intent removed: {key}")
            return self._core_intents.pop(key, None) is not None

    def intent_get_all(self) -> Dict[str, CoreIntent]:
        with self._data_lock:
            return self._core_intents.copy()

    def intent_clear_all(self) -> None:
        with self._data_lock:
            self._core_intents.clear()

    def intent_exists(self, another_intent: CoreIntent) -> bool:
        with self._data_lock:
            for intent in self._core_intents.values():
                if (
                    intent.intent_type == another_intent.intent_type
                    and intent.threat == another_intent.threat
                    and intent.host == another_intent.host
                    and not intent.timedout()
                ):
                    return True
            return False

    # Threat management methods

    def threat_add(self, threat: DetectedThreat) -> None:
        with self._data_lock:
            self._threats[threat.uid] = threat
            self._logger.info(f"Threat added: {threat.uid}")

    def threat_get(self, key: str) -> Optional[DetectedThreat]:
        with self._data_lock:
            return self._threats.get(key)
        
    def threat_update(self, key: str, threat: DetectedThreat) -> bool:
        with self._data_lock:
            if key in self._threats:
                self._threats[key] = threat
                self._logger.info(f"Threat updated: {key}")
                return True
            return False

    def threat_remove(self, key: str) -> bool:
        with self._data_lock:
            self._logger.info(f"Threat removed: {key}")
            return self._threats.pop(key, None) is not None

    def threat_get_all(self) -> Dict[str, DetectedThreat]:
        with self._data_lock:
            return self._threats.copy()

    def threat_clear_all(self) -> None:
        with self._data_lock:
            self._threats.clear()
    
    def threat_locate(self, another_threat: DetectedThreat) -> Optional[str]:
        with self._data_lock:
            for threat in self._threats.values():
                if (
                    threat.threat_type == another_threat.threat_type
                    and threat.threat_name == another_threat.threat_name
                    and threat.hosts == another_threat.hosts
                    and threat.status
                    in [
                        DetectedThreat.ThreatStatus.NEW,
                        DetectedThreat.ThreatStatus.UNDER_MITIGATION,
                        DetectedThreat.ThreatStatus.REINCIDENT,
                    ]
                    and not threat.is_expired()
                ):
                    return threat.uid
            return None

