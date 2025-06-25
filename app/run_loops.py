from database import es_client as es
import whatif_loop
import warnings
import config
import get_intents_script
import time
import requests
warnings.filterwarnings('ignore')

whatif_send_url = config.whatif_send_url
stored_intents_url = config.stored_intents_url

def run_whatif_loop_fun():
    whatif_loop.whatif_loop_fun(es, whatif_send_url)

def run_duration_check_loop():
    duration_check_2()

def duration_check_2():
    while True:
        intent_index = es.exists(index="stored_intents", id=1)
        if intent_index == True:
            resp1 = es.search(index="stored_intents", size=100, query={"match_all": {}})
            id_arr = []
            source_arr = []
            for hit in resp1['hits']['hits']:
                id_arr.append(hit["_id"])
                source_arr.append(hit["_source"])
            for source, id in zip(source_arr, id_arr):
                duration = 0
                if source['duration'] != '':
                    duration = int(source['duration'])
                time_elapsed = source['actual_time'] + duration
                #time_elapsed = source['actual_time'] + int(source['duration'])
                if time_elapsed <= time.time():
                    url_to_delete = stored_intents_url + "/" + str(source['intent_id'])
                    requests.delete(url_to_delete)
                time.sleep(0.5)
        time.sleep(0.5)

def duration_check():
    #time.sleep(2)
    while True:
        intent_index = es.exists(index="stored_intents", id=1)
        if intent_index == True:
            stored_intents_arr = get_intents_script.get_intent_fun(stored_intents_url)
            if len(stored_intents_arr) > 0:
                for i in range(len(stored_intents_arr)):
                    duration = 0
                    if stored_intents_arr[i]['duration'] != '':
                        duration = int(stored_intents_arr[i]['duration'])

                    time_elapsed = stored_intents_arr[i]['actual_time'] + duration
                    if time_elapsed <= time.time():
                        url_to_delete = stored_intents_url + "/" + str(stored_intents_arr[i]['intent_id'])
                        requests.delete(url_to_delete)
                    time.sleep(0.5)
        time.sleep(0.5)