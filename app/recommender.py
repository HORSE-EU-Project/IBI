from constants import Const
import datetime
from utils.log_config import setup_logging
from data.mitigations import MITIGATION_DATA
from db.elastic_search import ElasticSearchClient

logger = setup_logging(__file__)

class Recommender:

    def __init__(self):
        """
        Initialize the Recommender class.
        """
        self._es_client = ElasticSearchClient().get_client()

    def get_mitigation(self, intent):
        """
        Get mitigation actions based on intent type and threat.
        @param intent: The intent object containing type and threat.
        @return: List of mitigation actions.
        """
        intent_type = intent.get("intent_type")
        threat = intent.get("threat")
        possible_mitigations = MITIGATION_DATA.get(intent_type, {}).get(threat, [])
        # Get already associated mitigations for this intent
        associated_mitigations = self.get_associated_mitigations(intent.get("id"))
        # Filter out mitigations that are already associated
        available_mitigations = [m for m in possible_mitigations if m not in associated_mitigations]
        return available_mitigations
    

    def associate_mitigation(self, intent_id, mitigation_name):
        """
        Associate a mitigation action with an intent.

        @param intent_id: The ID of the intent.
        @param mitigation_name: The name of the mitigation action.
        """
        
        # Create the association document
        association_doc = {
            'intent_id': intent_id,
            'mitigation_name': mitigation_name,
            'timestamp': datetime.utcnow().isoformat()
        }

        # Store in Elasticsearch index
        self._es_client.index(
            index=Const.ASSOCIATIONS_INDEX, 
            body=association_doc
        )

        logger.info(f"Associating mitigation '{mitigation_name}' with intent ID '{intent_id}'")

    def get_associated_mitigations(self, intent_id):
        """
        Get all mitigations associated with a specific intent.

        @param intent_id: The ID of the intent.
        @return: List of associated mitigation names.
        """
        query = {
            "query": {
                "term": {"intent_id": intent_id}
            }
        }

        response = self._es_client.search(
            index=Const.ASSOCIATIONS_INDEX,
            body=query
        )

        associated_mitigations = []
        if response['hits']['hits']:
            for hit in response['hits']['hits']:
                associated_mitigations.append(hit['_source']['mitigation_name'])

        return associated_mitigations

        