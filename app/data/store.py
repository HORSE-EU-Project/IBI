from app.utils.log_config import setup_logging
from models.core_models import CoreIntent
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
                if intent.intent_type == another_intent.intent_type and \
                   intent.threat == another_intent.threat and \
                   intent.host == another_intent.host and \
                   not intent.timedout():
                    return True
            return False