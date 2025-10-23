from ast import Dict
import random
from data.store import InMemoryStore
from models.core_models import MitigationAction
from config import MITIGATION_ACTIONS

from utils.log_config import setup_logging

logger = setup_logging(__name__)

class StatusController:
    """
    The controller in charge of listng the deployed
    HORSE modules and also responsible for checking the staus of
    each module.
    Only HTTP/HTTPS status check are supported
    """

    MODULE_STATUS_ONLINE = "Online"
    MODULE_STATUS_OFFLINE = "Offline"

    list_of_modules = []
    module_status = {}

    def __init__(self) -> None:
        self.list_of_modules = MITIGATION_ACTIONS
        

    def get_status(self) -> Dict:
        for module in self.list_of_modules:
            self.module_status[module] = self._query_status()


    def _query_status(self, module_name) -> str:
        if random.random() > 0.5:
            return self.MODULE_STATUS_ONLINE
        else:
            return self.MODULE_STATUS_OFFLINE