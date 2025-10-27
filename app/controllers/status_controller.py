from ast import Dict
import random
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
    status = []
  

    def get_status(self) -> Dict:
        for module in MODULE_STATUS:
            self.status.append({
                "name": module["name"],
                "description": module["description"],
                "status": self._query_status(module)
            })
        return self.status


    def _query_status(self, module_object) -> str:
        self._logger.debug(f"Querying status of module {module_object['description']}")
        if random.random() > 0.5:
            return self.MODULE_STATUS_ONLINE
        else:
            return self.MODULE_STATUS_OFFLINE