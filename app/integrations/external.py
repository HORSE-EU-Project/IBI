"""
This class represents an external integration to the RTR service.
It gets the configuration from the YML configuration file and it tries
to establish an HTTP connection to the RTR service.

"""

import requests
import json
import config
from utils.log_config import setup_logging
from intent_manager import IntentManager


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
        self._logger = setup_logging(__file__)
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
        """Create a workflow for the RTR service."""
        im = IntentManager()
        workflow = {
            "command": "add",
            "intent_type": intent.get("intent_type"),
            "threat": intent.get("threat"),
            "attacked_host": intent.get("attacked_host"),
            "mitigation_host": intent.get("mitigation_host"),
            "action": {
                "name": "execute_test_1",
                "fields": {
                    "test_id": "1",
                    "modules": [
                        "Pre-processing",
                        "DEME",
                        "DTE",
                        "IBI",
                        "CKB",
                        "RTR",
                        "ePEM",
                        "CAS",
                    ],
                },
            },
            "duration": intent.get("duration"),
            "intent_id": im._get_intent_id(intent),
        }
        self._logger.debug(f"Workflow created: {workflow}")
        return workflow

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


class CKB:

    _logger = setup_logging(__file__)

    def __init__(self):
        self.ckb_url = config.CKB_URL
        self.headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.ckb_url:
            self.enabled = True
            self._mitigation_url = f"{self.ckb_url}/mitigations"
        else:
            self.enabled = False
            self._logger.info(f"Integration to CKB is disabled.")

    def query_ckb(self, attack_name=None):
        attacks = [
            "ntp_dos",
            "pfcf_dos",
            "dns_reflection_amplification",
            "hello_world",
            "ddos_amplification",
            "dns_amplification",
            "ddos_download_link",
            "data_poisoning",
            "multidomain",
            "mitm",
            "nf_exposure",
            "signaling_pfcp",
            "poisoning_and_amplification",
            "network_exposure",
        ]
        req_body = {}

        if attack_name is None or attack_name == "" or attack_name not in attacks:
            self._logger.info(f"Using default attack name")
            attack_name = "hello_world"
        req_body = {"attack_name": attack_name}

        if self.enabled:
            try:

                response = requests.post(
                    f"{self.ckb_url}/mitigations",
                    timeout=2,
                    headers=self.headers,
                    json=req_body,
                )
                response.raise_for_status()
                self._logger.info(f"CKB query successful for attacks.")
            except requests.exceptions.RequestException as e:
                self._logger.error(f"Error querying CKB for attacks: {e}")
        else:
            self._logger.warning(
                f"CKB integration is disabled. Sending query to logging system."
            )
            self._logger.info(f"CKB query body: {req_body}")


class ImpactAnalysisDT:

    _logger = setup_logging(__file__)

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

    def send_to_iadt(self, intent_id):
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
        intent_manager = IntentManager()
        intent_manager.update_status(intent_id, status)


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
