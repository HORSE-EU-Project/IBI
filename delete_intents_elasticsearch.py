import subprocess
import shlex
import time
from elasticsearch import Elasticsearch
#es = Elasticsearch('http://172.21.0.1:9200')

def delete_intents_elasticsearch_fun(elasticsearch_url, id_to_delete):
    es = Elasticsearch(elasticsearch_url)
    resp = es.search(index="stored_intents", size=100, query={"match_all": {}})
    print("Got %d Hits:" % resp['hits']['total']['value'])
    es.delete(index="stored_intents", id=id_to_delete)
    time.sleep(2)
    resp = es.search(index="stored_intents", size=100, query={"match_all": {}})
    print("Got %d Hits:" % resp['hits']['total']['value'])
    id_arr = []
    source_arr = []
    for hit in resp['hits']['hits']:
        source_arr.append(hit["_source"])
        id_arr.append(hit["_id"])
    print('id arr: ', id_arr)
    print('source arr: ', source_arr)
    new_source_arr = []
    #for i, id in zip(range(len(source_arr)), id_arr):
    id_change = 0
    for source, id in zip(source_arr, id_arr):
        new_doc = source
        print('new doc before: ', new_doc)
        new_doc['id'] = id_change + 1
        id_change += 1
        print('new doc after: ', new_doc)
        new_source_arr.append(new_doc)
        #for id in id_arr:
        es.update(index="stored_intents", id=id, doc=new_doc)
    #print(resp['result'])
    time.sleep(1)
    resp = es.search(index="stored_intents", size=100, query={"match_all": {}})
    print("Got %d Hits:" % resp['hits']['total']['value'])
    print('new source arr: ', new_source_arr)

    for hit in resp['hits']['hits']:
        es.delete(index="stored_intents", id=hit["_id"])

    for i in range(len(new_source_arr)):
        es.index(index="stored_intents", id=new_source_arr[i]["id"], document=new_source_arr[i])

    print('delete and reset completed')