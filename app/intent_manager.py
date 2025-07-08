import datetime
import uuid
from constants import Const
from utils.log_config import setup_logging
from db.elastic_search import ElasticSearchClient

logger = setup_logging(__file__)


class IntentManager:
    """
    This class is responsible for managing intents.
    It processes intents and calls the policy configurator based on the intent type.
    """

    INTENT_CREATED = "created"
    INTENT_UPDATED = "updated"

    def __init__(self):
        self._es_client = ElasticSearchClient().get_client()
        logger.info("IntentManager initialized")


    def process_intent_request(self, intent):
        """
        Process an intent request.
        If the intent already exists, it updates the status.
        If it does not exist, it creates a new intent.
        """
        logger.info(f"Processing intent request: {intent}")

        if self._intent_exists(intent):
            logger.debug(f"Intent {intent} already exists in the store")
            return self.INTENT_UPDATED
        else:
            logger.debug(f"Intent {intent} does not exist in the store, adding it")
            self.add(intent)
            return self.INTENT_CREATED

    
    def add(self, intent):
        # generate a unique ID for the intent
        intent_id = self._generate_id(intent)

        if not self._intent_exists(intent):
            # if intent does not exist in the ES, create a new intent
            logger.debug(f"Intent with ID {intent_id} does not exist, creating new intent")
            current_time = datetime.datetime.now(datetime.timezone.utc)
            intent_dict = {
                "id": intent_id,
                "intent_type": intent.intent_type,
                "threat": intent.threat,
                "host": intent.host,
                "duration": intent.duration,
                "timestamp": current_time,
                "status": Const.INTENT_STATUS_NEW,
                "timeout": current_time + datetime.timedelta(seconds=intent.duration)
            }
            self._es_client.index(index=Const.INTENTS_INDEX, id=intent_id, document=intent_dict)
            logger.info(f"New intent added to intent store. ID {intent_id}")

    
    def get_by_id(self, intent_id):
        """
        Retrieve an intent by its ID.
        """
        return self._es_client.get(index=Const.INTENTS_INDEX, id=intent_id)


    def get_all(self, status=None, intent_type=None):
        intents = []
        if status is None:
            query = {
                "query": {
                    "match_all": {}
                }
            }
            logger.info(f"Retrieving all intents from the store")
        else:
            query = {
                "query": {
                    "term": {
                        "status": status
                    }
                }
            }
            if intent_type is not None:
                query['query']['bool']['must'].append({"term": {"intent_type": intent_type}})
            logger.info(f"Retrieving intents with status '{status}' and type '{intent_type}' from the store")
        try:
            
            response = self._es_client.search(
                    index=Const.INTENTS_INDEX,
                    body=query
            )
            for hit in response['hits']['hits']:
                intent = hit['_source']
                intents.append(intent)
            return intents
        except Exception as e:
            logger.error(f"Error querying Elasticsearch: {e}")
            return []
        
    
    def update_status(self, intent_id, status):
        """
        Update the status of an intent.
        """
        if self._es_client.exists(index=Const.INTENTS_INDEX, id=intent_id):
            logger.info(f"Updating status of intent {intent_id} to {status}")
            self._es_client.update(
                index=Const.INTENTS_INDEX,
                id=intent_id,
                body={
                    "doc": {
                        "status": status
                    }
                }
            )
        else:
            logger.warning(f"Intent with ID {intent_id} does not exist, cannot update status")


    
    def _generate_id(self, intent) -> str:
        """
        Generate a unique ID for the intent.
        """
        return str(uuid.uuid4())  # Using UUID for unique intent ID

    def _get_intent_id(self, intent) -> str:
        """
        Get the ID of the intent in the intent store.
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"intent_type": intent.intent_type}},
                        {"term": {"threat": intent.threat}},
                        {"term": {"host": intent.host}}
                    ],
                    "must_not": [
                        {"term": {"status": Const.INTENT_STATUS_MITIGATED}}
                    ]
                }
            }
        }
        response = self._es_client.search(
            index=Const.INTENTS_INDEX,
            body=query
        )
        if response['hits']['total']['value'] > 0:
            return response['hits']['hits'][0]['_id']
        return None


    def _intent_exists(self, intent) -> bool:
        """
        Check if an intent already exists in the Elasticsearch index.
        """
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"intent_type": intent.intent_type}},
                        {"term": {"threat": intent.threat}},
                        {"term": {"host": intent.host}}
                    ],
                    "must_not": [
                        {"term": {"status": Const.INTENT_STATUS_MITIGATED}}
                    ]
                }
            }
        }

        try:
            response = self._es_client.search(
                index=Const.INTENTS_INDEX,
                body=query
            )
            return response['hits']['total']['value'] > 0
        except Exception as e:
            logger.error(f"Error checking if intent exists: {e}")
            return False
    


# def execute_intent_manager(intent):
#     #stores the intents retrieved from the intent api
#     #retrieved_intents_arr = []
#     print('intent manager started - waiting for intent')

#     # the various APIs to be connected to
#     workflow_url = config.workflow_url
#     whatif_send_url = config.whatif_send_url
#     stored_intents_url = config.stored_intents_url

#     intent_dict_main = {}
#     intent_dict_main['intent_type'] = intent.intent_type
#     intent_dict_main['threat'] = intent.threat
#     intent_dict_main['host'] = intent.host
#     intent_dict_main['duration'] = intent.duration

#     #if new intent got from the intent api is not the same with the last intent stored in retrieved_intents_arr
#     #or if retrieved_intents_arr is empty, then call the policy configurator function
#     #l = len(retrieved_intents_arr)
#     #if l != 0:
#     #    if retrieved_intents_arr[l-1] != intent_dict_main:
#     #        retrieved_intents_arr.append(intent_dict_main)
#     if intent_dict_main['intent_type'] == 'mitigation' or intent_dict_main['intent_type'] == 'prevention':
#         policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url, whatif_send_url,
#                                                     stored_intents_url)
#     #elif intent_dict_main['intent_type'] == 'prevention':
#     #    policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url,
#     #                                          whatif_send_url, stored_intents_url, elasticsearch_url)
#         #MOVED TO WHAT IF SEND FUN
#         '''intent_index = es.exists(index="awaiting_intents", id=1)
#         if intent_index == True:
#             resp1 = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
#             total = resp1['hits']['total']['value']
#             id = total + 1
#             es.index(index="awaiting_intents", id=id, document=whatif_question)
#         else:
#             es.index(index="awaiting_intents", id=1, document=whatif_question)'''
#     else:
#         print('incorrect intent type')


# def execute_intent_manager_qos(intent):
#     #stores the intents retrieved from the intent api
#     #retrieved_intents_arr = []
#     print('intent manager started - waiting for QOS intent')

#     # the various APIs to be connected to
#     workflow_url = config.workflow_url
#     whatif_send_url = config.whatif_send_url
#     stored_qos_intents_url = config.stored_qos_intents_url

#     intent_dict_main = {}
#     intent_dict_main['intent_type'] = intent.intent_type
#     intent_dict_main['name'] = intent.name
#     intent_dict_main['value'] = intent.value
#     intent_dict_main['unit'] = intent.unit
#     intent_dict_main['host'] = intent.host


#     #if new intent got from the intent api is not the same with the last intent stored in retrieved_intents_arr
#     #or if retrieved_intents_arr is empty, then call the policy configurator function
#     #l = len(retrieved_intents_arr)
#     #if l != 0:
#     #    if retrieved_intents_arr[l-1] != intent_dict_main:
#     #        retrieved_intents_arr.append(intent_dict_main)
#     if intent_dict_main['intent_type'] == 'qos_ntp' or intent_dict_main['intent_type'] == 'qos_dns' \
#     or intent_dict_main['intent_type'] == 'qos_pfcp':
#     #if intent_dict_main['intent_type'] == 'mitigation':
#         policy_configurator.policy_configurator_fun_qos(intent_dict_main, workflow_url, stored_qos_intents_url)




#old functions
'''
def execute_intent_manager(intent):
    # stores the intents retrieved from the intent api
    retrieved_intents_arr = []
    print('intent manager started - waiting for intent')

    # the various APIs to be connected to
    workflow_url = config.workflow_url
    whatif_send_url = config.whatif_send_url
    stored_intents_url = config.stored_intents_url
    elasticsearch_url = config.elasticsearch_url
    es = Elasticsearch(elasticsearch_url)

    intent_dict_main = {}
    intent_dict_main['intent_type'] = intent.intent_type
    intent_dict_main['threat'] = intent.threat
    intent_dict_main['host'] = intent.host
    intent_dict_main['duration'] = intent.duration

    # if new intent got from the intent api is not the same with the last intent stored in retrieved_intents_arr
    # or if retrieved_intents_arr is empty, then call the policy configurator function
    l = len(retrieved_intents_arr)
    if l != 0:
        if retrieved_intents_arr[l - 1] != intent_dict_main:
            retrieved_intents_arr.append(intent_dict_main)
            if intent_dict_main['intent_type'] == 'mitigation':
                policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url, whatif_send_url,
                                                            stored_intents_url, elasticsearch_url)
            elif intent_dict_main['intent_type'] == 'prevention':
                whatif_question = policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url,
                                                                              whatif_send_url, stored_intents_url,
                                                                              elasticsearch_url)
                intent_index = es.exists(index="awaiting_intents", id=1)
                if intent_index == True:
                    resp1 = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
                    total = resp1['hits']['total']['value']
                    id = total + 1
                    es.index(index="awaiting_intents", id=id, document=whatif_question)
                else:
                    es.index(index="awaiting_intents", id=1, document=whatif_question)
            else:
                print('incorrect intent type')

    else:
        retrieved_intents_arr.append(intent_dict_main)
        if intent_dict_main['intent_type'] == 'mitigation':
            policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url, whatif_send_url,
                                                        stored_intents_url, elasticsearch_url)
        elif intent_dict_main['intent_type'] == 'prevention':
            whatif_question = policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url,
                                                                          whatif_send_url,
                                                                          stored_intents_url, elasticsearch_url)
            intent_index = es.exists(index="awaiting_intents", id=1)
            if intent_index == True:
                resp1 = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
                total = resp1['hits']['total']['value']
                id = total + 1
                es.index(index="awaiting_intents", id=id, document=whatif_question)
            else:
                es.index(index="awaiting_intents", id=1, document=whatif_question)
        else:
            print('incorrect intent type')


def execute_intent_manager_qos(intent):
    # stores the intents retrieved from the intent api
    retrieved_intents_arr = []
    print('intent manager started - waiting for QOS intent')

    # the various APIs to be connected to
    workflow_url = config.workflow_url
    whatif_send_url = config.whatif_send_url
    stored_qos_intents_url = config.stored_qos_intents_url
    elasticsearch_url = config.elasticsearch_url
    es = Elasticsearch(elasticsearch_url)

    intent_dict_main = {}
    intent_dict_main['intent_type'] = intent.intent_type
    intent_dict_main['name'] = intent.name
    intent_dict_main['value'] = intent.value
    intent_dict_main['host'] = intent.host

    # if new intent got from the intent api is not the same with the last intent stored in retrieved_intents_arr
    # or if retrieved_intents_arr is empty, then call the policy configurator function
    l = len(retrieved_intents_arr)
    if l != 0:
        if retrieved_intents_arr[l - 1] != intent_dict_main:
            retrieved_intents_arr.append(intent_dict_main)
            if intent_dict_main['intent_type'] == 'qos_ntp' or intent_dict_main['intent_type'] == 'qos_dns' \
                    or intent_dict_main['intent_type'] == 'qos_pfcp':
                # if intent_dict_main['intent_type'] == 'mitigation':
                policy_configurator.policy_configurator_fun_qos(intent_dict_main, workflow_url, stored_qos_intents_url,
                                                                elasticsearch_url)


    else:
        retrieved_intents_arr.append(intent_dict_main)
        if intent_dict_main['intent_type'] == 'qos_ntp' or intent_dict_main['intent_type'] == 'qos_dns' \
                or intent_dict_main['intent_type'] == 'qos_pfcp':
            policy_configurator.policy_configurator_fun_qos(intent_dict_main, workflow_url, stored_qos_intents_url,
                                                            elasticsearch_url)
'''
