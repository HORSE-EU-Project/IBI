import requests
from constants import Const
from models.core_models import MitigationAction
import config
from utils.log_config import setup_logging

class CASClient:
    """
    Client for the Compliance Asssurance Service
    """

    _logger = setup_logging(__name__)

    VALID = "valid"
    INVALID = "invalid"
    PARTIAL = "partial"

    def __init__(self):
        self.headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        self.cas_url = config.CAS_URL
        if self.cas_url and self.cas_url != "":
            self.enabled = True
            self.cas_url = f"{self.cas_url}/api/external-data"
        else:
            self.enabled = False
            self._logger.info(f"Integration to CKB is disabled.")

    def tune_mitigation(self, mitigation_action: MitigationAction):
        """
        Tune the fields of the mitigation action to match the expected format.
        """
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


        
        # Example tuning logic, adjust as needed
        # if "percentage" in mitigation_action:
        #     mitigation_action["fields"]["percentage"] = int(
        #         mitigation_action["fields"]["percentage"]
        #     )
        return mitigation_action
                    

    def validate(self, intent, mitigation_action):
        # TODO: implement validation logic
        return self.VALID
        doc_body = {
            "input": {
                "command": "add",
                "intent_type": intent.get("intent_type"),
                "threat": intent.get("threat"),
                "attacked_host": intent.get("host"),
                "mitigation_host": "dns-s",
                "action": {
                    "name": "random",
                    "intent_id": intent.get("id"),
                    "fields": {"percentage": 50},
                },
                "duration": intent.get("duration"),
                "intent_id": intent.get("id"),
            }
        }
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
                response.raise_for_status()
                self._logger.debug(f"CAS document sent successfully: {response.status_code}")
                # Check the answer from CAS
                if response.status_code == 200:
                    answer = response.json()
                    if answer.get("allow") == "true":
                        self._logger.info(f"CAS validation successful for intent ID: {intent_id}")
                        return self.VALID
                    elif answer.get("allow") == "false":
                        if int(answer.get("pass_percentage")) == 0:
                            return self.INVALID
                        else:
                            return self.PARTIAL
                    else:
                        self._logger.warning(f"CAS validation failed for intent ID: {intent_id}")
                else:
                    self._logger.error(f"CAS validation failed with status code: {response.status_code}")

            except requests.exceptions.RequestException as e:
                self._logger.error(f"Error sending document to CAS: {e}")
            return self.VALID
