from elasticsearch import Elasticsearch
import send_workflows
import time
import random
import string
import pandas as pd
import delete_intents_elasticsearch
import config


port = config.port
elastic_host = config.elastic_host
elastic_port = config.elastic_port
parameters = config.parameters
workflow_url = config.workflow_url
elasticsearch_url = config.elasticsearch_url
es = Elasticsearch(elasticsearch_url)

def whatif_send_fun(policy_dict, whatif_send_url):
    sent_whatif = []
    # empty dict containing the elements of the what-if question which are the matched policy attributes
    whatif_question = {}
    id_digits = 9
    whatif_id = ''.join(random.choices(string.ascii_uppercase +
                                       string.digits, k=id_digits))
    print('intent type is prevention, sending what-if question')
    whatif_question['command'] = 'send_what_if'
    whatif_question['intent_type'] = policy_dict['intent_type']
    whatif_question['threat'] = policy_dict['threat']
    whatif_question['host'] = policy_dict['host']
    whatif_question['action'] = policy_dict['action']
    whatif_question['duration'] = str(policy_dict['duration'])
    whatif_question['id'] = whatif_id
    l = len(sent_whatif)
    if l != 0 and whatif_question != sent_whatif[l-1]:
        sent_whatif.append(whatif_question)
        # send what-if question to the what_if_send_url
        send_workflows.send_workflow_fun(whatif_send_url, whatif_question)
    elif l == 0:
        sent_whatif.append(whatif_question)
        # send what-if question to the what_if_send_url
        send_workflows.send_workflow_fun(whatif_send_url, whatif_question)
    return whatif_question

#the function runs through the awaiting intents elasticsearch index every 60 secs
#and sends what-if questions to the SAN for the hosts in the awaiting intents index
def whatif_loop_fun(es, whatif_send_url):
    #print('entered whatif loop')
    while True:
        intent_index = es.exists(index="awaiting_intents", id=1)
        if intent_index == True:
            resp1 = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
            id_arr = []
            source_arr = []
            for hit in resp1['hits']['hits']:
                id_arr.append(hit["_id"])
                source_arr.append(hit["_source"])
            for source, id in zip(source_arr, id_arr):
                whatif_question = source
                whatif_question['command'] = 'send_what_if'
                send_workflows.send_workflow_fun(whatif_send_url, whatif_question)
        time.sleep(60)

#when a what-if answer is received from the SAN
#the IBI proceeds with the intent if the response from the SAN is acceptable
def whatif_receive_fun(whatif_receive):
    import policy_configurator
    stored_intents_url = config.stored_intents_url
    whatif_answer = {}
    if whatif_receive.what_if_response == 'ok':
        print('proceeding with intent')
        whatif_answer['command'] = 'add'
        whatif_answer['intent_type'] = whatif_receive.intent_type
        whatif_answer['threat'] = whatif_receive.threat
        whatif_answer['host'] = whatif_receive.host
        whatif_answer['action'] = whatif_receive.action
        whatif_answer['duration'] = whatif_receive.duration
        whatif_answer['id'] = whatif_receive.id
        whatif_answer['what_if_response'] = whatif_receive.what_if_response
        df_policy = pd.read_csv(config.policy_store_directory)
        for ind in df_policy.index:
            if df_policy['action'][ind] == whatif_answer['action']:
                whatif_answer['priority'] = df_policy['priority'][ind]
        policy_configurator.policy_configurator_fun_2(workflow_url, stored_intents_url, elasticsearch_url,
                                                      whatif_answer)
    else:
        print('not proceeding with intent')
    resp = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
    for ind in range(len(resp['hits']['hits'])):
        hit1 = resp['hits']['hits'][ind]['_source']
        if hit1['intent_type'] == whatif_answer['intent_type'] and hit1['threat'] == whatif_answer['threat'] and \
                str(hit1['host']) == str(whatif_answer['host']) and hit1['action'] == whatif_answer['action'] and \
                str(hit1['duration']) == str(whatif_answer['duration']) and hit1['id'] == whatif_answer['id']:
            delete_intents_elasticsearch.delete_intents_elasticsearch_fun(elasticsearch_url, resp['hits']['hits'][ind]['_id'],
                                                        "awaiting_intents")

def del_whatif_fun(policy_dict):
    resp = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
    for ind in range(len(resp['hits']['hits'])):
        hit1 = resp['hits']['hits'][ind]['_source']
        if hit1['threat'] == policy_dict['threat'] and hit1['host'] == policy_dict['host']:
            delete_intents_elasticsearch.delete_intents_elasticsearch_fun(elasticsearch_url, resp['hits']['hits'][ind]['_id'],
                                                        "awaiting_intents")


