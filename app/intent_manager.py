import policy_configurator
from elasticsearch import Elasticsearch
import config

def execute_intent_manager(intent):
    #stores the intents retrieved from the intent api
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

    #if new intent got from the intent api is not the same with the last intent stored in retrieved_intents_arr
    #or if retrieved_intents_arr is empty, then call the policy configurator function
    l = len(retrieved_intents_arr)
    if l != 0:
        if retrieved_intents_arr[l-1] != intent_dict_main:
            retrieved_intents_arr.append(intent_dict_main)
            if intent_dict_main['intent_type'] == 'mitigation':
                policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url, whatif_send_url,
                                                            stored_intents_url, elasticsearch_url)
            elif intent_dict_main['intent_type'] == 'prevention':
                whatif_question = policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url,
                                                        whatif_send_url, stored_intents_url, elasticsearch_url)
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
            whatif_question = policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url, whatif_send_url,
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
    #stores the intents retrieved from the intent api
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


    #if new intent got from the intent api is not the same with the last intent stored in retrieved_intents_arr
    #or if retrieved_intents_arr is empty, then call the policy configurator function
    l = len(retrieved_intents_arr)
    if l != 0:
        if retrieved_intents_arr[l-1] != intent_dict_main:
            retrieved_intents_arr.append(intent_dict_main)
            if intent_dict_main['intent_type'] == 'qos_ntp' or intent_dict_main['intent_type'] == 'qos_dns' \
            or intent_dict_main['intent_type'] == 'qos_pfcp':
            #if intent_dict_main['intent_type'] == 'mitigation':
                policy_configurator.policy_configurator_fun_qos(intent_dict_main, workflow_url, stored_qos_intents_url,
                                                                elasticsearch_url)
                '''elif intent_dict_main['intent_type'] == 'prevention':
                    whatif_question = policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url,
                                                            whatif_send_url, stored_intents_url, elasticsearch_url)
                    intent_index = es.exists(index="awaiting_intents", id=1)
                    if intent_index == True:
                        resp1 = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
                        total = resp1['hits']['total']['value']
                        id = total + 1
                        es.index(index="awaiting_intents", id=id, document=whatif_question)
                    else:
                        es.index(index="awaiting_intents", id=1, document=whatif_question)
                else:
                    print('incorrect intent type')'''

    else:
        retrieved_intents_arr.append(intent_dict_main)
        if intent_dict_main['intent_type'] == 'qos_ntp' or intent_dict_main['intent_type'] == 'qos_dns' \
                or intent_dict_main['intent_type'] == 'qos_pfcp':
            policy_configurator.policy_configurator_fun_qos(intent_dict_main, workflow_url, stored_qos_intents_url,
                                                                elasticsearch_url)
        '''if intent_dict_main['intent_type'] == 'mitigation':
            policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url, whatif_send_url,
                           stored_intents_url, elasticsearch_url)
        elif intent_dict_main['intent_type'] == 'prevention':
            whatif_question = policy_configurator.policy_configurator_fun(intent_dict_main, workflow_url, whatif_send_url,
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
            print('incorrect intent type')'''



