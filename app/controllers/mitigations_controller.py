from data.store import InMemoryStore
from models.core_models import MitigationAction
from config import MITIGATION_ACTIONS

from utils.log_config import setup_logging

logger = setup_logging(__name__)

class MitigationsController:

    """
    Static Method to populate the In Memory database with the mitigation actions
    Loads mitigation actions from the configuration file
    """
    @staticmethod
    def populate_mitigation_actions():
        store = InMemoryStore()
        
        # Load mitigation actions from configuration
        mitigations = []
        for action_config in MITIGATION_ACTIONS:
            try:
                # Create MitigationAction from config data
                mitigation = MitigationAction(
                    name=action_config["name"],
                    category=action_config["category"],
                    threats=action_config["threats"],
                    fields=action_config["fields"]
                )
                
                # Set optional fields if present in config
                if "priority" in action_config:
                    mitigation.priority = action_config["priority"]
                if "enabled" in action_config:
                    mitigation.enabled = action_config["enabled"]
                
                mitigations.append(mitigation)
                logger.debug(f"Loaded mitigation action: {action_config['name']}")
                
            except KeyError as e:
                logger.error(f"Missing required field {e} in mitigation action config: {action_config}")
            except Exception as e:
                logger.error(f"Error loading mitigation action {action_config.get('name', 'unknown')}: {e}")
        
        # Store all mitigation actions
        for mitigation in mitigations:
            store.mitigation_add(mitigation)
        
        logger.info(f"Populated {len(mitigations)} mitigation actions from configuration")

    @staticmethod
    def dump_mitigation_actions():
        """
        Dump all mitigation actions to the logger
        """
        store = InMemoryStore()
        mitigations = store.mitigation_get_all()
        logger.debug("Dumping Mitigation Actions:")
        for mitigation in mitigations:
            logger.debug(mitigation.to_dict())