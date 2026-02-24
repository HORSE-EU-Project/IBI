"""
This class represents an external integration to the RTR service.
It gets the configuration from the YML configuration file and it tries
to establish an HTTP connection to the RTR service.
"""

import requests
import json
import config
from uuid import uuid4
from utils.log_config import setup_logging
from models.core_models import CoreIntent, MitigationAction
from recommender import Recommender


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
        self._recommender = Recommender()
        self.rtr_url = config.RTR_URL
        self.rtr_username = config.RTR_USER
        self.rtr_password = config.RTR_PASSWORD
        self.rtr_email = config.RTR_EMAIL
        self._enabled = bool(self.rtr_url and self.rtr_username and self.rtr_password)
        # call login method to authenticate
        self.access_token = ""
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
        except requests.exceptions.HTTPError as e:
            if hasattr(e, "response") and e.response is not None:
                self._logger.info(f"RTR registration error response: {e.response.text}")
        except requests.exceptions.MissingSchema as e:
            self._logger.info(
                f"CKB integration is disabled. Sending query to logging system."
            )
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
        login_data = (
            f"username={self.rtr_username}"
            f"&password={self.rtr_password}"
            f"&scope="
            f"&client_id="
            f"&client_secret="
        )
        login_headers = {
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        # POST LOGIN REQUEST
        try:
            # Use requests.post with the correct URL, headers, and data as in the curl command
            response = requests.post(
                f"{self.rtr_url}/login", headers=login_headers, data=login_data
            )
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
            self._logger.debug(f"RTR login successful: {response.status_code}")
            if "access_token" in response.json():
                self.access_token = response.json()["access_token"]
                self._logger.debug(f"Authentication token: {self.access_token}")
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

    def enforce_mitigation(
        self, intent: CoreIntent, mitigation_action: MitigationAction
    ):
        # Create a workflow for the RTR service
        rtr_message = self.create_workflow(intent, mitigation_action)
        # Send the workflow to the RTR service
        self.send_workflow(rtr_message)

    def create_workflow(self, intent: CoreIntent, mitigation_action: MitigationAction):
        fields_template = {}
        for key, value in mitigation_action.parameters.items():
            fields_template[key] = value
            self._logger.debug(
                f"Field {key} with value {value} added to the action template"
            )

        # Fix for UPC testbed
        fields_template["duration"] = intent.duration
        self._logger.debug(
            f"Field duration with value {str(intent.duration)} added to the action template. FIX for UPC!"
        )

        action_template = {"name": mitigation_action.name, "fields": fields_template}

        attacked_host = ""
        if (
            mitigation_action.category == MitigationAction.MitigationCategory.PREVENTION
            and intent.threat == "ddos_downlink"
        ):
            attacked_host = self._recommender._resolve_hostnames("ue_panel")
        else:
            attacked_host = intent.host[0] if intent.host else ""

        message_template = {
            "command": "add",
            "intent_type": intent.intent_type.value,
            "threat": intent.threat,
            "attacked_host": attacked_host,
            "mitigation_host": self._recommender.get_mitigation_host(
                intent, mitigation_action
            ),
            "action": action_template,
            "duration": intent.duration,
            "intent_id": str(uuid4()),
        }
        return message_template

    def send_workflow(self, workflow):
        if not self._enabled:
            self._logger.info("Connection to RTR is not established.")
            self._logger.info(f"Workflow details: {json.dumps(workflow, indent=4)}")
            return

        """Send a workflow to the RTR service."""
        headers_for_action_post = {
            "accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        self._logger.debug(f"Sending workflow to RTR: {json.dumps(workflow, indent=4)}")
        try:
            response = requests.post(
                f"{self.rtr_url}/actions",
                headers=headers_for_action_post,
                json=workflow,
            )
            # response.raise_for_status()
            if response.status_code in [200, 201]:
                self._logger.info(f"Workflow sent successfully: {response.status_code}")
            elif response.status_code == 400:
                self._logger.info(
                    f"Workflow exists: {response.status_code} {response.text}"
                )
            else:
                self._logger.error(
                    f"Workflow sent failed: {response.status_code} {response.text}"
                )
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
