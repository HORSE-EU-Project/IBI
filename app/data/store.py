import threading
from typing import Dict, List, Optional
from datetime import datetime
from models.core_models import CoreIntent, DTJob, DetectedThreat, MitigationAction
from utils.log_config import setup_logging


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
            self._available_actions: Dict[str, MitigationAction] = {}
            self._associations: Dict[str, List[MitigationAction]] = {}
            self._dt_jobs: List[DTJob] = []
            self._dt_available: bool = True
            self._ibi_compromised: bool = False
            self._logger = setup_logging(__name__)
            self._initialized = True

    """
    Core Intent management methods
    """

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

    def intent_get_all(self) -> List[CoreIntent]:
        with self._data_lock:
            return [intent for intent in self._core_intents.values()]

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


    """
    Detected threat management methods
    """
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

    def threat_get_all(self) -> List[DetectedThreat]:
        with self._data_lock:
            return [threat for threat in self._threats.values()]

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
                        DetectedThreat.ThreatStatus.UNDER_EMULATION,
                        DetectedThreat.ThreatStatus.UNDER_MITIGATION,
                        DetectedThreat.ThreatStatus.REINCIDENT,
                    ]
                    and not threat.is_expired()
                ):
                    return threat.uid
            return None

    def expire_old_threats(self) -> None:
        with self._data_lock:
            for threat in list(self._threats.values()):
                if threat.is_expired():
                    threat.status = DetectedThreat.ThreatStatus.MITIGATED
                    # Should update the "Last Update?"
                    threat.last_update = int(datetime.now().timestamp())
                    self._logger.info(f"Threat expired: {threat.uid}")


    """
    Mitigation actions management methods
    """
    def mitigation_add(self, action: MitigationAction) -> None:
        with self._data_lock:
            self._available_actions[action.uid] = action
            self._logger.debug(f"Mitigation action added: {action.uid} -- {action.name}")


    def mitigation_get(self, key: str) -> Optional[MitigationAction]:
        with self._data_lock:
            return self._available_actions.get(key)


    def mitigation_get_all(self) -> List[MitigationAction]:
        with self._data_lock:
            return [action for action in self._available_actions.values()]

    
    def mitigation_update(self, key: str, action: MitigationAction) -> bool:
        with self._data_lock:
            if key in self._available_actions:
                self._available_actions[key] = action
                self._logger.debug(f"Mitigation action updated: {key}")
                return True
            return False     

    """
    Keeps track of associations between the MitigationAction and Threat
    """
    def association_add(self, threat_id: str, mitigation: MitigationAction) -> None:
        with self._data_lock:
            if threat_id not in self._associations:
                self._associations[threat_id] = []
            self._associations[threat_id].append(mitigation)
            self._logger.debug(f"Association added for intent {threat_id} with mitigation {mitigation.uid} -- {mitigation.name}")


    def association_get(self, threat_id: str) -> Optional[List[MitigationAction]]:
        with self._data_lock:
            return self._associations.get(threat_id)


    def association_update(self, threat_id: str, mitigation: MitigationAction) -> bool:
        with self._data_lock:
            if threat_id in self._associations:
                self._associations[threat_id] = mitigation
                self._logger.debug(f"Association updated for intent {threat_id} with mitigation {mitigation.uid}")
                return True
            return False
    
    
    """
    Digital Twin Jobs management methods
    """
    def dt_job_add(self, job: DTJob) -> None:
        with self._data_lock:
            # Throw an exception if a DTJob with the same threat_id already exists
            # for existing_job in self._dt_jobs:
            #     if existing_job.threat_id == job.threat_id:
            #         raise Exception(f"DTJob with threat_id {job.threat_id} already exists.")
            self._dt_jobs.append(job)
            self._logger.debug(f"IA-NDT job added: {job.uid}")


    def dt_job_update(self, job_id: str, updated_job: DTJob) -> bool:
        with self._data_lock:
            for index in range(len(self._dt_jobs)):
                if self._dt_jobs[index].uid == job_id:
                    self._dt_jobs[index] = updated_job
                    self._logger.debug(f"IA-NDT job updated: {job_id}")
                    return True
            return False


    def dt_job_get(self, job_id: str) -> Optional[DTJob]:
        with self._data_lock:
            for job in self._dt_jobs:
                if job.uid == job_id and job.status not in [DTJob.JobStatus.EXPIRED]:
                    return job
            return None

    def dt_job_get_by_threat(self, threat_id: str) -> Optional[DTJob]:
        with self._data_lock:
            for job in self._dt_jobs:
                if job.threat_id == threat_id and job.status not in [DTJob.JobStatus.EXPIRED]:
                    return job
            return None


    def dt_job_exists(self, job: DTJob) -> bool:
        """
        Check if there there is already a job for the same threat and action.
        """
        with self._data_lock:
            for existing_job in self._dt_jobs:
                if existing_job.threat_id == job.threat_id and \
                    existing_job.mitigation_id == job.mitigation_id and \
                    existing_job.status not in [DTJob.JobStatus.EXPIRED]:
                    return True
            return False

    def dt_job_get_all(self, expired: bool = False) -> List[DTJob]:
        with self._data_lock:
            return [job for job in self._dt_jobs if job.status not in [DTJob.JobStatus.EXPIRED] or expired]


    def dt_job_delete(self, thread_id: str) -> bool:
        """
        Delete a DTJob from the list using the DTJob.thread_id.
        Returns True if a job was deleted, False otherwise.
        """
        with self._data_lock:
            for idx, job in enumerate(self._dt_jobs):
                if job.threat_id == thread_id and job.status not in [DTJob.JobStatus.EXPIRED]:
                    self._dt_jobs[idx].status = DTJob.JobStatus.EXPIRED
                    self._logger.debug(f"IA-NDT job deleted: {job.uid}")
                    return True
            return False


    """
    Controls the availability of the IA-NDT
    """
    def dt_is_available(self) -> bool:
        with self._data_lock:
            return self._dt_available

    def dt_set_available(self) -> None:
        self._logger.debug("Setting IA-NDT to available")
        with self._data_lock:
            self._dt_available = True

    def dt_set_busy(self) -> None:
        self._logger.debug("Setting IA-NDT to busy")
        with self._data_lock:
            self._dt_available = False