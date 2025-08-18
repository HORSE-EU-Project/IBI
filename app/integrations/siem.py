import requests
import config
import logging
from logging.handlers import SysLogHandler
from utils.log_config import setup_logging

class CustomSIEM:
    """
    Client for the external syslog service.
    """

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

    def send_log(self, message):
        if not self.enabled:
            self._logger.warning(f"Syslog integration is disabled. Sending log to application logging system.")
            self._logger.info(f"Log message: {message}")
            return

        try:
            self._remote_logger.info(message)
            self._logger.info(f"Log sent to Syslog: {message}")
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Error sending log to Syslog: {e}")