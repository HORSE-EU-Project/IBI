import requests
import config
from utils.log_config import setup_logging
from models.core_models import DetectedThreat, MitigationAction


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