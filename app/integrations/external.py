"""
This class represents an external integration to the RTR service.
It gets the configuration from the YML configuration file and it tries
to establish an HTTP connection to the RTR service.

"""

import requests
import json
import config
import logging
from threading import Lock
from logging.handlers import SysLogHandler
from utils.log_config import setup_logging
from data.store import InMemoryStore
from models.core_models import DetectedThreat, MitigationAction
from difflib import get_close_matches

class RTR:
    _instance = None

    def __new__(cls, config_path="config.yml"):
        if cls._instance is None:
            cls._instance = super(RTR, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path="config.yml"):
        if self._initialized:
            return
        self._logger = setup_logging(__name__)
        self.rtr_url = config.RTR_URL
        self.rtr_username = config.RTR_USER
        self.rtr_password = config.RTR_PASSWORD
        self.rtr_email = config.RTR_EMAIL
        # call login method to authenticate
        self.token = ""
        self.reg_headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        self._register()
        self._login()
        self._initialized = True

    def _register(self):
        """Register a user on the RTR service."""
        reg_data = {
            "username": self.rtr_username,
            "email": self.rtr_email,
            "password": self.rtr_password,
        }

        try:
            response = requests.post(
                f"{self.rtr_url}/register",
                headers=self.reg_headers,
                data=json.dumps(reg_data),
            )
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
            self._logger.info(f"RTR registration successful: {response.status_code}")
        except requests.exceptions.MissingSchema as e:
            self._logger.info(f"CKB integration is disabled. Sending query to logging system.")
            self._logger.info(f"{ json.dumps(reg_data) }")  
        except requests.exceptions.ConnectionError as e:
            self._logger.error(
                f"Error connecting to RTR service during registration: {e}"
            )
            raise  # Re-raise the exception after logging
        except requests.exceptions.Timeout as e:
            self._logger.error(f"Timeout occurred during RTR registration: {e}")
            raise
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Error during RTR registration: {e}")
            if hasattr(e, "response") and e.response is not None:
                self._logger.error(
                    f"RTR registration error response: {e.response.text}"
                )
            raise

    def _login(self):
        """Login to the RTR service and retrieve an access token."""
        if not self.rtr_url or not self.rtr_username or not self.rtr_password:
            self._logger.error("RTR service URL, username, or password not configured.")
            return
        login_data = {
            "grant_type": "",
            "username": self.rtr_username,
            "password": self.rtr_password,
            "scope": "",
            "client_id": "",
            "client_secret": "",
        }
        # POST LOGIN REQUEST
        try:
            response = requests.post(
                f"{self.rtr_url}/login", headers=self.reg_headers, data=login_data
            )
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
            self._logger.info(f"RTR login successful: {response.status_code}")
            if "access_token" in response.json():
                self.access_token = response.json()["access_token"]
                self._logger.info(f"Authentication token: {self.access_token}")
        except requests.exceptions.ConnectionError as e:
            self._logger.error(f"Error connecting to RTR service during login: {e}")
            raise  # Re-raise the exception after logging
        except requests.exceptions.Timeout as e:
            self._logger.error(f"Timeout occurred during RTR login: {e}")
            raise
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Error during RTR login: {e}")
            if hasattr(e, "response") and e.response is not None:
                self._logger.error(f"RTR login error response: {e.response.text}")
            raise

    def create_workflow(self, intent, mitigation_action):
        # """Create a workflow for the RTR service."""
        # im = DTEController()
        # workflow = {
        #     "command": "add",
        #     "intent_type": intent.get("intent_type"),
        #     "threat": intent.get("threat"),
        #     "attacked_host": intent.get("attacked_host"),
        #     "mitigation_host": intent.get("mitigation_host"),
        #     "action": mitigation_action,
        #     "duration": intent.get("duration"),
        #     "intent_id": im._get_intent_id(intent),
        # }
        # self._logger.debug(f"Workflow created: {workflow}")
        # return workflow
        pass

    def send_workflow(self, workflow):
        if not self.access_token:
            self._logger.error(
                "Connection to RTR is not established. The workflow will be printed to the log."
            )
            self._logger.info(f"Workflow details: {workflow}")
            return

        """Send a workflow to the RTR service."""
        headers_for_action_post = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        try:
            response = requests.post(
                f"{self.rtr_url}/actions",
                headers=headers_for_action_post,
                json=workflow,
            )
            response.raise_for_status()
            self._logger.info(f"Workflow sent successfully: {response.status_code}")
        except requests.exceptions.ConnectionError as e:
            self._logger.error(
                f"Error connecting to RTR service when sending workflow: {e}"
            )
            raise
        except requests.exceptions.Timeout as e:
            self._logger.error(f"Timeout occurred when sending workflow to RTR: {e}")
            raise
        except requests.exceptions.RequestException as e:
            self._logger.error(f"Error sending workflow to RTR: {e}")
            if hasattr(e, "response") and e.response is not None:
                self._logger.error(f"RTR workflow error response: {e.response.text}")
            raise


class ImpactAnalysisDT:
    """
    Class to interact with the Impact Analysis Digital Twin (IA-NDT).
    It sends workflows to the IA-NDT and handles responses. The class implementas a queue
    to ensure that only one request at time is sent to the IA-NDT.
    """

    class IADTACtion:
        """
        Class to represent an action in the Impact Analysis Digital Twin.
        """
        def __init__(self, threat: DetectedThreat, action: MitigationAction):
            self.theat = threat
            self.action = action
            self.kpi_before = None
            self.kpi_after = None

    _logger = setup_logging(__name__)
    _queue = []

    # Class-level queue and worker to guarantee only one in-flight request

    _messages = {
        "block": {
            "id": "0002",
            "topology_name": "horse_ddos",
            "attack": "DDoS_reverse",
            "what-condition": {
                "KPIs": {
                    "element": {"node": "dns-c1", "interface": "eth1"},
                    "metric": "packets-per-second",
                    "duration": "30s",
                }
            },
            "if-condition": {
                "action": {
                    "type": "block_pod_ip",
                    "value": "internet",
                    "unit": "*",
                    "duration": "30s",
                },
                "element": {
                    "node": "ceos2",
                    "interface": "eth1",
                    "network": "*",
                    "ref": "ceos2_eth1_*",
                },
            },
        },
        "monitor": {
            "id": "0003",
            "topology_name": "horse_ddos",
            "attack": "DDoS_reverse",
            "what-condition": {
                "KPIs": {
                    "element": {"node": "dns-c1", "interface": "eth1"},
                    "metric": "packets-per-second",
                    "duration": "30s",
                }
            },
            "if-condition": {
                "action": {
                    "type": "monitor",
                    "value": "*",
                    "unit": "*",
                    "duration": "30s",
                },
                "element": {
                    "node": "*",
                    "interface": "*",
                    "network": "*",
                    "ref": "*_*_*",
                },
            },
        },
        "limit": {
            "id": "0001",
            "topology_name": "horse_ddos",
            "attack": "DDoS_reverse",
            "what-condition": {
                "KPIs": {
                    "element": {"node": "dns-c1", "interface": "eth1"},
                    "metric": "packets-per-second",
                    "duration": "30s",
                }
            },
            "if-condition": {
                "action": {
                    "type": "rate_limit",
                    "value": "1",
                    "unit": "mbps",
                    "duration": "30s",
                },
                "element": {
                    "node": "ceos2",
                    "interface": "eth1",
                    "network": "*",
                    "ref": "ceos2_eth1_*",
                },
            },
        },
    }



    def __init__(self):
        self.iadt_url = config.IADT_URL
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.iadt_url and self.iadt_url != "":
            self.enabled = True
        else:
            self.enabled = False

    def enqueue_simulation(self, threat: DetectedThreat, action: MitigationAction):
        action = ImpactAnalysisDT.IADTACtion(threat, action)
        self._queue.append(action)
        self._logger.info(f"Action {action.action.uid} for threat {threat.uid} added to the IA-NDT queue.")


    def process_queue(self):
        if self._queue:
            current_action = self._queue.pop(0)
            self.send_to_iadt(current_action)


    def send_to_iadt(self, action: IADTACtion):
        # Message to send to the Impact Analysis Digital Twin
        iadt_message = self._messages["block"]
        iadt_message["id"] = intent_id

        if not self.enabled:
            self._logger.warning(
                f"Impact Analysis Digital Twin is not enabled. Commands will be sent to logging system."
            )
            self._logger.info(f"Impact Analysis Digital Twin message: {iadt_message}")
        else:
            try:
                response = requests.post(
                    f"{self.iadt_url}/from_ibi",
                    headers=self.headers,
                    json=iadt_message,
                )
                response.raise_for_status()
                print(
                    f"Workflow sent to Impact Analysis Digital Twin successfully: {response.status_code}"
                )
            except requests.exceptions.RequestException as e:
                print(f"Error sending workflow to Impact Analysis Digital Twin: {e}")

    def update_intent_status(self, intent_id, status):
        """
        Update the status of an intent in the Impact Analysis Digital Twin.
        """
        # TODO: update status from NDT

    def log_received_answer(self, answer_dict):
        """
        Log the received answer from the Impact Analysis Digital Twin.
        """
        if not self.enabled:
            self._logger.warning(
                f"Impact Analysis Digital Twin is not enabled. Answer will be logged."
            )
            self._logger.info(f"Received answer: {answer_dict}")
            return

        # Log the received answer
        self._logger.info(
            f"Received answer from Impact Analysis Digital Twin: {answer_dict}"
        )


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

    def _tune_mitigation_fields(self, mitigation_action):
        """
        Tune the fields of the mitigation action to match the expected format.
        """
        # Example tuning logic, adjust as needed
        # if "percentage" in mitigation_action:
        #     mitigation_action["fields"]["percentage"] = int(
        #         mitigation_action["fields"]["percentage"]
        #     )
        return mitigation_action


    def process_mitigation(self, intent, mitigations):
        for mitigation in mitigations:
            
            result = self.validate(intent, mitigation)
            
            if result == self.VALID:
                return mitigation
            else:
                if result == self.INVALID:
                    self._logger.info(f"Mitigation {mitigation} is invalid, trying next mitigation")
                    continue
                elif result == self.PARTIAL:
                    tuned_mitigation = self._tune_mitigation_fields(mitigation)
                    return tuned_mitigation
                    

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


class ExternalSyslog:
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