"""
This class represents an external integration to the RTR service.
It gets the configuration from the YML configuration file and it tries
to establish an HTTP connection to the RTR service.

"""

import requests
import json
import config
from utils.log_config import setup_logging


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
            print(f"RTR registration successful: {response.status_code}")
        except requests.exceptions.ConnectionError as e:
            print(f"Error connecting to RTR service during registration: {e}")
            raise  # Re-raise the exception after logging
        except requests.exceptions.Timeout as e:
            print(f"Timeout occurred during RTR registration: {e}")
            raise
        except requests.exceptions.RequestException as e:
            print(f"Error during RTR registration: {e}")
            if hasattr(e, "response") and e.response is not None:
                print(f"RTR registration error response: {e.response.text}")
            raise

    def _login(self):
        """Login to the RTR service and retrieve an access token."""
        if not self.rtr_url or not self.rtr_username or not self.rtr_password:
            print("RTR service URL, username, or password not configured.")
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
            print(f"RTR login successful: {response.status_code}")
            if "access_token" in response.json():
                self.access_token = response.json()["access_token"]
                print(f"Authentication token: {self.access_token}")
        except requests.exceptions.ConnectionError as e:
            print(f"Error connecting to RTR service during login: {e}")
            raise  # Re-raise the exception after logging
        except requests.exceptions.Timeout as e:
            print(f"Timeout occurred during RTR login: {e}")
            raise
        except requests.exceptions.RequestException as e:
            print(f"Error during RTR login: {e}")
            if hasattr(e, "response") and e.response is not None:
                print(f"RTR login error response: {e.response.text}")
            raise

    def send_workflow(self, workflow):
        if not self.access_token:
            print(
                "Connection to RTR is not established. The workflow will be printed to the log."
            )
            print(f"Workflow details: {workflow}")
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
            print(f"Workflow sent successfully: {response.status_code}")
        except requests.exceptions.ConnectionError as e:
            print(f"Error connecting to RTR service when sending workflow: {e}")
            raise
        except requests.exceptions.Timeout as e:
            print(f"Timeout occurred when sending workflow to RTR: {e}")
            raise
        except requests.exceptions.RequestException as e:
            print(f"Error sending workflow to RTR: {e}")
            if hasattr(e, "response") and e.response is not None:
                print(f"RTR workflow error response: {e.response.text}")
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
            self._logger.warning(f"CKB integration is disabled. Sending query to logging system.")
            self._logger.info(f"CKB query body: {req_body}")
