from data.store import InMemoryStore
from models.core_models import DTJob
from utils.log_config import setup_logging


class IANDTController:

    def __init__(self):
        self._store = InMemoryStore()
        self._logger = setup_logging(__name__)

    def process_response(self, job_id, value):
        """
        Process the response from the IANDT.
        """
        self._logger.info(f"Processing response from IANDT for job {job_id} with value {value}")
        # Get the DTJob object from the store
        dt_job = self._store.dt_job_get(job_id)
        if dt_job is None:
            self._logger.error(f"DTJob object not found for job {job_id}")
            return
        # Update the DTJob object with the new value
        if dt_job.kpi_before is None:
            dt_job.update_kpi_before(value)
            self._store.dt_set_available()
            self._logger.info(f"DTJob object updated (monitor) for job {job_id} with value {value}")
        else:
            dt_job.update_kpi_after(value)
            dt_job.update_status(DTJob.JobStatus.COMPLETED)
            self._store.dt_set_available()
            self._logger.info(f"DTJob object updated (mitigation) for job {job_id} with value {value}")
        self._store.dt_job_update(job_id, dt_job)
        