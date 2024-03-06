import delete_command
from elasticsearch import Elasticsearch
import delete_intents_elasticsearch
import time
import config

#function for deleting intents
def select_delete_fun(to_delete):
    workflow_url = config.workflow_url
    elasticsearch_url = config.elasticsearch_url
    es = Elasticsearch(elasticsearch_url)

    print('to delete intent')

    resp = es.search(index="stored_intents", size=100, query={"match_all": {}})
    time.sleep(1)
    for ind in range(len(resp['hits']['hits'])):
        intent_index = es.exists(index="stored_intents", id=1)
        # repeat the process for the next intent in the intent store
        if ind < len(resp['hits']['hits']) and intent_index == True:
            hit1 = resp['hits']['hits'][ind]['_source']
            if hit1['intent_type'] == to_delete['intent_type'] and hit1['threat'] == to_delete['threat'] and \
                    str(hit1['host']) == str(to_delete['host']) and hit1['action'] == to_delete['action'] and \
                    str(hit1['duration']) == str(to_delete['duration']) and hit1['intent_id'] == to_delete['intent_id']:
                #send delete intent workflow to RTR
                delete_command.delete_intents_fun(hit1['intent_id'], workflow_url)
                # delete intent on elasticsearch
                delete_intents_elasticsearch.delete_intents_elasticsearch_fun(elasticsearch_url,
                                                                        resp['hits']['hits'][ind]['_id'], "stored_intents")
