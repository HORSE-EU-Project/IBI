from types import TracebackType
import requests
from ast import Dict
from config import MODULE_STATUS
from utils.log_config import setup_logging

class StatusController:
    """
    The controller in charge of listng the deployed
    HORSE modules and also responsible for checking the staus of
    each module.
    Only HTTP/HTTPS status check are supported
    """
    _logger = setup_logging(__name__)

    MODULE_STATUS_ONLINE = "Online"
    MODULE_STATUS_OFFLINE = "Offline"
    list_of_modules = []

    def get_status(self) -> Dict:
        # No modules to check
        if MODULE_STATUS is None:
            return []
        # Check the status of each module in configuration file
        status = []
        for module in MODULE_STATUS:
            status.append({
                "name": module["name"],
                "description": module["description"],
                "status": self._query_status(module)
            })
        return status


    def _query_status(self, module_object) -> str:
        self._logger.debug(f"Querying status of module {module_object['url']}")
        try:
            response = requests.get(module_object['url'])
            if response.status_code == int(module_object['expected_code']):
                return self.MODULE_STATUS_ONLINE
            else:
                return self.MODULE_STATUS_OFFLINE
        except requests.exceptions.ConnectionError as e:
            self._logger.debug(f"Error connecting to module {module_object['url']}: {e}")
            return self.MODULE_STATUS_OFFLINE
        except requests.exceptions.Timeout as e:
            self._logger.debug(f"Timeout connecting to module {module_object['url']}: {e}")
            return self.MODULE_STATUS_OFFLINE
        except requests.exceptions.RequestException as e:
            self._logger.debug(f"Error connecting to module {module_object['url']}: {e}")
            return self.MODULE_STATUS_OFFLINE