import yaml
from elasticsearch import Elasticsearch

def empty_fun():
    with open('/code/app/config.yml') as f:
        parameters = yaml.safe_load(f)
    elastic_host = parameters['elasticsearch_ip']
    elastic_port = parameters['elasticsearch_port']
    elasticsearch_url = "http://" + elastic_host + ":" + elastic_port
    es = Elasticsearch(elasticsearch_url)
    #delete existing data on the intent store on elasticsearch when u start new deployment
    int_ind = False
    for i in list(range(100)):
        intent_index = es.exists(index="stored_intents", id=str(i))
        if intent_index == True:
            int_ind = True
    if int_ind == True:
        es.indices.refresh(index="stored_intents")
        resp = es.search(index="stored_intents", size=100, query={"match_all": {}})
        total = resp['hits']['total']['value']
        #print('total: ', total)
        if total != 0:
            id_arr = []
            for hit in resp['hits']['hits']:
                id_arr.append(hit["_id"])
            #print('id arr: ', id_arr)
            for id in id_arr:
                es.delete(index="stored_intents", id=id)

    #delete existing data on awaiting intents on elasticsearch when u start new deployment
    int_ind = False
    for i in list(range(100)):
        intent_index = es.exists(index="awaiting_intents", id=str(i))
        if intent_index == True:
            int_ind = True
    if int_ind == True:
        es.indices.refresh(index="awaiting_intents")
        resp = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
        total = resp['hits']['total']['value']
        #print('total: ', total)
        if total != 0:
            id_arr = []
            for hit in resp['hits']['hits']:
                id_arr.append(hit["_id"])
            #print('id arr: ', id_arr)
            for id in id_arr:
                es.delete(index="awaiting_intents", id=id)

