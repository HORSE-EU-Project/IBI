import requests
import config
import logging
from enum import Enum
from logging.handlers import SysLogHandler
from models.core_models import DetectedThreat
from utils.log_config import setup_logging

class CustomSIEM:
    """
    Client for the external syslog service.
    """

    class AlarmType(Enum):
        NEW = "new"
        MITIGATED = "mitigated"

    _logger = setup_logging(__name__)
    _syslog_remote = None
    _remote_logger = None

    def __init__(self):
        self.syslog_addr = config.SYSLOG_IP
        if self.syslog_addr and self.syslog_addr != "":
            self.enabled = True
            self._syslog_remote = SysLogHandler(address=(self.syslog_addr, config.SYSLOG_PORT))
            self._remote_logger = logging.getLogger("remote_logger")
            self._remote_logger.setLevel(logging.INFO)
            self._remote_logger.addHandler(self._syslog_remote)
        else:
            self.enabled = False
            self._logger.info(f"Integration to Syslog is disabled.")

    def send_log(self, threat: DetectedThreat, status: AlarmType) -> None:
        # Create the log message
        if status == self.AlarmType.NEW:
            message = f"New threat detected: {threat.uid} of type {threat.threat_type}"
        elif status == self.AlarmType.MITIGATED:
            message = f"Threat mitigated: {threat.uid} of type {threat.threat_type}"
        # Send the alert or log to STDOUT
        if not self.enabled:
            self._logger.warning(f"Syslog integration is disabled. Sending log to application logging system.")
            self._logger.info(f"Log message: {message}")
        else:
            try:
                self._remote_logger.info(message)
                self._logger.info(f"Log sent to Syslog: {message}")
            except requests.exceptions.RequestException as e:
                self._logger.error(f"Error sending log to Syslog: {e}")