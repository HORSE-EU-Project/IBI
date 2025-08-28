import json
import requests
import config
from constants import Const
from models.core_models import CoreIntent, MitigationAction
from recommender import Recommender
from utils.log_config import setup_logging
from data.store import InMemoryStore

class CASClient:
    """
    Client for the Compliance Asssurance Service
    """

    _logger = setup_logging(__name__)

    VALID = "valid"
    INVALID = "invalid"
    PARTIAL = "partial"

    _cas_actions = {
        "rate_limiting": "router_rate_limiting",
    }

    def __init__(self):
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.cas_url = config.CAS_URL
        self._recommender = Recommender()
        self._store = InMemoryStore()
        if self.cas_url and self.cas_url != "":
            self.enabled = True
            self.cas_url = f"{self.cas_url}/api/external-data"
        else:
            self.enabled = False
            self._logger.info(f"Integration to CKB is disabled.")

    def tune_mitigation(self, mitigation_action: MitigationAction):
        """
        This method tunes the fields of the given mitigation action to match the expected format
        required by the Compliance Assurance Service (CAS).

        Args:
            mitigation_action (MitigationAction): The mitigation action object whose fields need to be tuned.

        Returns:
            MitigationAction: The tuned mitigation action with updated fields as required by CAS.
        """
        # TODO: use graphRAG to send context to LLM and tune the fields using generative AI
        if mitigation_action.name == "rate_limiting":
            if 'rate' in mitigation_action.parameters.keys():
                rate_value = mitigation_action.parameters['rate']
                if isinstance(rate_value, str) and rate_value.endswith('mbps'):
                    try:
                        int_part = int(''.join(filter(str.isdigit, rate_value)))
                        new_rate = f"{int_part + Const.CAS_RATE_MITITING_INCREMENT}mbps"
                        mitigation_action.parameters['rate'] = new_rate
                    except Exception as e:
                        self._logger.error(f"Error tuning rate value: {e}")
        return mitigation_action
                    

    def validate(self, intent: CoreIntent, mitigation_action: MitigationAction):
        """
        Validate a mitigation action for a given intent using the Compliance Assurance Service (CAS).

        This method sends the intent and mitigation action details to the CAS endpoint for validation.
        It returns one of three possible validation results:
            - VALID: The mitigation action is fully compliant.
            - INVALID: The mitigation action is not compliant.
            - PARTIAL: The mitigation action is partially compliant (some requirements are met).

        Args:
            intent (CoreIntent): The intent object containing threat and context information.
            mitigation_action (MitigationAction): The mitigation action to be validated.

        Returns:
            str: One of the class constants (VALID, INVALID, PARTIAL) indicating the validation result.
        """
        doc_body = self._cas_message(intent, mitigation_action)
        if not self.enabled:
            self._logger.warning(f"CAS is not enabled. Sending data to logging system.")
            self._logger.info(f"Document body: {doc_body}")
            return self.VALID
        else:
            try:
                response = requests.post(
                    f"{self.cas_url}",
                    headers=self.headers,
                    json=doc_body,
                )
                # response.raise_for_status()
                self._logger.debug(f"CAS document sent: {doc_body}")
                # Check the answer from CAS
                if response.status_code == 200:
                    answer = response.json()
                    
                    # Checking for intent spoofing
                    if "continue" in answer.keys() and bool(answer.get("continue")) == False:
                        self._logger.debug(f"CAS validation failed for intent spoofing. Attack of type {intent.threat} not detected.")
                        self._store._ibi_compromised = True
                        return self.INVALID

                    # Mitigation is 100% compliant
                    if answer.get("allow") == "true":
                        self._logger.info(f"CAS validation successful for intent mitigation: {mitigation_action.uid}")
                        return self.VALID
                    elif answer.get("allow") == "false":
                        if int(answer.get("pass_percentage")) == 0: 
                            # Mitigation is 0% compliant (should select another mitigation action)
                            return self.INVALID
                        else:
                            # Mitigation is partially compliant (mitigation actions should be tuned)
                            return self.PARTIAL
                    else:
                        self._logger.warning(f"CAS validation failed for intent mitigation: {mitigation_action.uid}")
                else:
                    self._logger.error(f"CAS validation failed with status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                self._logger.error(f"Error sending document to CAS: {e}")
            # Catch any other result (since no other return statement were reached)
            return self.INVALID


    def _cas_message(self, intent: CoreIntent, mitigation_action: MitigationAction) -> str:
        """
        Generate the CAS message body for validation.

        This method constructs the message payload to be sent to the CAS (Central Authorization Service)
        for validating a mitigation action against a given intent. The message includes details about
        the intent, the mitigation action, and relevant fields required by CAS.

        Args:
            intent (CoreIntent): The intent object containing threat and context information.
            mitigation_action (MitigationAction): The mitigation action to be validated.

        Returns:
            str: The message body (as a dictionary) to be sent to CAS for validation.
        """
        fields_template = {}
        for key, value in mitigation_action.parameters.items():
            fields_template[key] = value
            self._logger.debug(f"Field {key} with value {value} added to the action template")

        action_template = {
            "name": self._cas_actions.get(mitigation_action.name, mitigation_action.name),
            "fields": fields_template
        }
        message_template = {"input": {
            "command": "add",
            "intent_type": intent.intent_type.value,
            "threat": intent.threat,
            "attacked_host": intent.host,
            "mitigation_host": self._recommender.get_mitigation_host(intent, mitigation_action),
            "action": action_template,
            "duration": intent.duration,
            "intent_id": intent.uid
        }}
        return message_template
