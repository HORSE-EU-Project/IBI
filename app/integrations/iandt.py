import requests
import config
import threading
import time
from enum import Enum
from constants import Const
from utils.log_config import setup_logging
from data.store import InMemoryStore
from models.core_models import DetectedThreat, MitigationAction, DTJob


class ImpactAnalysisDT:
    """
    Class to interact with the Impact Analysis Digital Twin (IA-NDT).
    It sends workflows to the IA-NDT and handles responses. The class implementas a queue
    to ensure that only one request at time is sent to the IA-NDT.
    """

    class JobType(Enum):
        MEASUREMENT = "MEASUREMENT"
        SIMULATION = "SIMULATION"

    _store = None
    _logger = None
    _queue = []   # List[(DTJob, JobType)]

    # Class-level queue and worker to guarantee only one in-flight request

    _messages = {
        "block": {
            "id": "",
            "topology_name": "horse_ddos",
            "attack": "DDoS_reverse",
            "what-condition": {
                "KPIs": {
                    "element": {"node": "dns-c1", "interface": "eth1"},
                    "metric": "bytes-per-second",
                    "duration": "15s",
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
            "id": "",
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
        "rate_limit": {
            "id": "",
            "topology_name": "horse_ddos",
            "attack": "DDoS_reverse",
            "what-condition": {
                "KPIs": {
                    "element": {"node": "dns-c1", "interface": "eth1"},
                    "metric": "packets-per-second",
                    "duration": "15s",
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
        self._store = InMemoryStore()
        self._logger = setup_logging(__name__)
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
        dt_job = DTJob(threat.uid, action.uid)
        dt_job.set_mitigation_obj(action)
        measure_task = tuple([dt_job, ImpactAnalysisDT.JobType.MEASUREMENT])
        action_task = tuple([dt_job, ImpactAnalysisDT.JobType.SIMULATION])
        
        self._queue.append(measure_task)
        self._queue.append(action_task)
        self._logger.info(f"New job added to the queue: Threat: {threat.uid}, Action: {action.uid}")


    def process_queued_jobs(self):
        if self._queue and self._store.dt_is_available():
            (current_job, job_type) = self._queue.pop(0)  # Task type is either MEASUREMENT or SIMULATION
            if not self._store.dt_job_exists(current_job):
                self._store.dt_job_add(current_job)
            
            if job_type == ImpactAnalysisDT.JobType.MEASUREMENT:
                # if there is already a measurement value for the same threat, 
                # copy the value and skipt the measurement task
                # Workaround: IA-NDT cannot handle multiple measurement requests for the same threat
                for existing_dt_job in self._store._dt_jobs:
                    if existing_dt_job.threat_id == current_job.threat_id and existing_dt_job.kpi_before is not None:
                        current_job.update_kpi_before(existing_dt_job.kpi_before)
                        self._store.dt_job_update(current_job.uid, current_job)
                        self._logger.debug(f"Skipping measurement task for threat {current_job.threat_id} because it already has a measurement value")
                        return
                # If there is no measurement value for the same threat, send the measurement request
                message = self._get_monitor_msg(current_job)
            elif job_type == ImpactAnalysisDT.JobType.SIMULATION:
                message = self._get_simulation_msg(current_job)
            # Send the message via REST API
            self.send_iandt_message(message)
        else:
            if len(self._queue) == 0:
                self._logger.debug("IA-NDT queue is empty waiting for next cycle")
            if not self._store.dt_is_available():
                self._logger.debug("IA-NDT is not available, waiting for next cycle")

    
    def _get_monitor_msg(self, dt_job: DTJob) -> dict:
        """
        Send a measurement request to the Impact Analysis Digital Twin.
        """
        # Get the threat name from the detected threat
        threat_obj = self._store.threat_get(dt_job.threat_id)

        if threat_obj.threat_name == "dns_amplification":
            what_device = "ceos3"
            what_iface = "eth2"
        elif threat_obj.threat_name in ["ddos_download", "ddos_download_link"]:
            what_device = "dns-c1"
            what_iface = "eth1"
        else:
            what_device = "ceos3"
            what_iface = "eth2"

        message = self._messages["monitor"]
        message["id"] = dt_job.uid
        message["attack"] = self._dt_attack_name(threat_obj.threat_name)
        message["what-condition"]["KPIs"]["element"]["node"] = what_device
        message["what-condition"]["KPIs"]["element"]["interface"] = what_iface
        message["what-condition"]["KPIs"]["duration"] = "30s"
        message["if-condition"]["action"]["duration"] = "30s"
        return message


    def _get_simulation_msg(self, dt_job: DTJob) -> dict:
        """
        Send a simulation request to the Impact Analysis Digital Twin.
        """
        # Get the threat name from the detected threat
        threat_name = self._store.threat_get(dt_job.threat_id).threat_name
        # Get the mitigation action from the store
        mitigation_obj = dt_job.mitigation_obj  # Mitigation object from the job

        if mitigation_obj.name in ["dns_rate_limiting", "rate_limiting"]:
            message = self._messages["rate_limit"]
            
            if threat_name == "dns_amplification":
                message["what-condition"]["KPIs"]["element"]["node"] = "ceos3"
                message["what-condition"]["KPIs"]["element"]["interface"] = "eth2"
                message["if-condition"]["element"]["node"] = "ceos3"
                message["if-condition"]["element"]["interface"] = "eth2"
                message["if-condition"]["element"]["network"] = "*"
                message["if-condition"]["element"]["ref"] = "ceos3_eth2_*"
            
            elif threat_name in ["ddos_download", "ddos_download_link"]:
                message["what-condition"]["KPIs"]["element"]["node"] = "dns-c1"
                message["what-condition"]["KPIs"]["element"]["interface"] = "eth1"
                message["if-condition"]["element"]["node"] = "ceos2"
                message["if-condition"]["element"]["interface"] = "eth1"
                message["if-condition"]["element"]["network"] = "*"
                message["if-condition"]["element"]["ref"] = "ceos2_eth1_*"

        elif mitigation_obj.name == "block_pod_address":
            message = self._messages["block"]
            if threat_name == "dns_amplification":
                message["what-condition"]["KPIs"]["element"]["node"] = "ceos3"
                message["what-condition"]["KPIs"]["element"]["interface"] = "eth2"
                message["if-condition"]["action"]["value"] = "dns-c1"
                message["if-condition"]["element"]["node"] = "ceos3"
                message["if-condition"]["element"]["interface"] = "eth1"
                message["if-condition"]["element"]["network"] = "*"
                message["if-condition"]["element"]["ref"] = "ceos3_eth1_*"
            
            elif threat_name in ["ddos_download", "ddos_download_link"]:
                message["what-condition"]["KPIs"]["element"]["node"] = "dns-c1"
                message["what-condition"]["KPIs"]["element"]["interface"] = "eth1"
                message["if-condition"]["action"]["value"] = "internet"
                message["if-condition"]["element"]["node"] = "ceos2"
                message["if-condition"]["element"]["interface"] = "eth1"
                message["if-condition"]["element"]["network"] = "*"
                message["if-condition"]["element"]["ref"] = "ceos2_eth1_*"
        # Alaways update the id of the DT Job
        message["id"] = dt_job.uid
        return message


    def send_iandt_message(self, message: dict):
        self._store.dt_set_busy()
        # Message to send to the Impact Analysis Digital Twin
        if not self.enabled:
            self._logger.warning(
                f"Impact Analysis Digital Twin is not enabled. Commands will be sent to logging system."
            )
            self._logger.warning(f"Impact Analysis Digital Twin message: {message}")
            
            # Schedule a mock response if in development mode
            if Const.APP_ENV == Const.APP_ENV_DEV:
                self._schedule_mock_response(message)
        else:
            try:
                response = requests.post(
                    f"{self.iadt_url}/from_ibi",
                    headers=self.headers,
                    json=message,
                )
                response.raise_for_status()
                self._logger.info(f"Message sent to IA-NDT. Response status: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Error sending workflow to Impact Analysis Digital Twin: {e}")


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

    def check_results(self, threat_id: str, kpi_before: float, kpi_after: float) -> bool:
        """
        Check if the result is good.
        """
        return kpi_after < kpi_before * Const.IADT_PPS_THRESHOLD

    def _dt_attack_name(self, from_threat: str) -> str:
        """
        Convert a threat name to an attack name for the Digital Twin.

        This is a workaround because the NDT does not follow the naming convention
        agreed in the rest of the HORSE architecture.

        @param from_threat: The name of the threat (From DTE)
        @return: The corresponding attack name for the Digital Twin
        """
        names = {
            "dns_ddos": "DDoS_DNS",
            "ddos_download": "DDoS_Downlink",
            "ddos_download_link": "DDoS_Downlink",
            "dns_amplification": "DNS_Amplification",
        }
        return names.get(from_threat, from_threat)
    
    
    def _schedule_mock_response(self, original_message: dict):
        """
        Schedule a POST request to the impact-analysis endpoint with a mock digital twin answer
        when the integration is disabled and running in development mode.
        """
        def send_mock_response():
            # Wait a bit to simulate processing time
            time.sleep(2)
            
            # Create mock response based on the original message
            mock_response = self._create_mock_response(original_message)
            
            # Send POST request to the impact-analysis endpoint
            try:
                response = requests.post(
                    f"http://{Const.APP_HOST}:{Const.APP_PORT}/impact-analysis",
                    headers=self.headers,
                    json=mock_response,
                )
                response.raise_for_status()
                self._logger.info(f"Mock response sent to impact-analysis endpoint. Status: {response.status_code}")
            except requests.exceptions.RequestException as e:
                self._logger.error(f"Error sending mock response to impact-analysis endpoint: {e}")
        
        # Start the mock response in a separate thread
        thread = threading.Thread(target=send_mock_response, daemon=True)
        thread.start()
        self._logger.info(f"Scheduled mock response for message ID: {original_message.get('id', 'unknown')}")


    def _create_mock_response(self, original_message: dict) -> dict:
        """
        Create a mock response based on the original message sent to the digital twin.
        The response follows the JSON structure from iandt.rest file.
        """
        # Determine if this is a monitor or simulation message based on the action type
        action_type = original_message.get("if-condition", {}).get("action", {}).get("type", "")
        
        # Create base response structure
        mock_response = {
            "id": original_message.get("id", ""),
            "topology_name": original_message.get("topology_name", "horse_ddos"),
            "attack": original_message.get("attack", "DDoS_reverse"),
            "what": {
                "KPIs": {
                    "element": {
                        "node": original_message.get("what-condition", {}).get("KPIs", {}).get("element", {}).get("node", "ceos2"),
                        "interface": original_message.get("what-condition", {}).get("KPIs", {}).get("element", {}).get("interface", "eth1")
                    },
                    "metric": original_message.get("what-condition", {}).get("KPIs", {}).get("metric", "packets-per-second"),
                    "result": {
                        "value": "",
                        "unit": "packets-per-second"
                    }
                }
            }
        }
        
        # Set different values based on whether it's a monitor or simulation
        if action_type == "monitor":
            # Monitor response - higher packet rate (before mitigation)
            mock_response["what"]["KPIs"]["result"]["value"] = "20000"
        else:
            # Simulation response - lower packet rate (after mitigation)
            mock_response["what"]["KPIs"]["result"]["value"] = "18000"
        
        return mock_response