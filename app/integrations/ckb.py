import requests
import config
import json
from utils.log_config import setup_logging
from difflib import get_close_matches

class CKB:

    _logger = setup_logging(__name__)
    _attacks = [
        "ntp_dos",
        "pfcf_dos",
        "dns_reflection_amplification",
        "hello_world",
        "ddos_amplification",
        "dns_amplification",
        "ddos_download_link",
        "ddos_downlink",
        "data_poisoning",
        "multidomain",
        "mitm",
        "nf_exposure",
        "signaling_pfcp",
        "poisoning_and_amplification",
        "network_exposure",
    ]

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

    def get_attack_by_similarity(self, attack_name):
        """
        Get an attack by its name or a similar name.
        """
        # Use built-in string similarity matching
        matches = get_close_matches(attack_name, self._attacks, n=1, cutoff=0.3)
        if matches:
            self._logger.debug(f"Found similar attack: {matches[0]} for input: {attack_name}")
            return matches[0]
        else:
            self._logger.debug(f"Using default attack name")
            return "hello_world"


    def query_ckb(self, attack_name=None):
        req_body = {}
        attack_name = self.get_attack_by_similarity(attack_name)
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
                self._logger.debug(f"CKB query successful for attacks. Message sent: {json.dumps(req_body, indent=4)}")
                self._logger.info(f"CKB query successful for attacks.")
            except requests.exceptions.RequestException as e:
                self._logger.error(f"Error querying CKB for attacks: {e}")
        else:
            self._logger.warning(
                f"CKB integration is disabled. Sending query to logging system."
            )
            self._logger.info(f"CKB query body: {req_body}")