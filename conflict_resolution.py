import requests

import delete_command
import time
from elasticsearch import Elasticsearch
import delete_intents_elasticsearch
import get_intents


#function to resolve conflict in policies
def conflict_fun(df, ind, intent_host_arr, intent_dict_main, policy_dict, workflow_url, stored_intents_url,
                 elasticsearch_url):
    es = Elasticsearch(elasticsearch_url)
    # if an existing intent conflicts with new intent then resolve the conflict
    if df['host'][ind] in intent_host_arr and df['threat'][ind] == intent_dict_main['threat'] and policy_dict[
        'priority'] < df['priority'][ind]:

        #intent_host_arr is the array containing the host(s) for which the intent(s) apply
        for i in range(len(intent_host_arr)):
            if ind < len(df.index) and not df.empty:
                if intent_host_arr[i] == df['host'][ind] and df['threat'][ind] == intent_dict_main['threat'] and policy_dict[
        'priority'] < df['priority'][ind]:
                    #delete intent from stored intents api
                    stored_intents_arr = get_intents.get_intent_fun(stored_intents_url)
                    print('stored intents array: ', stored_intents_arr)
                    for j in range(len(stored_intents_arr)):
                        st_dict = stored_intents_arr[j]
                        print('st dict: ', st_dict)
                        '''if st_dict['intent_type'] == df['intent_type'][ind] and st_dict['threat'] == df['threat'][ind] and \
                                st_dict['host'] == df['host'][ind] and st_dict['action'] == df['action'][ind] and \
                                st_dict['duration'] == df['duration'][ind] and st_dict['intent_id'] == df['intent_id'][ind]:'''
                        if st_dict['intent_id'] == df['intent_id'][ind]:
                            url_to_delete = stored_intents_url + "/" + str(st_dict['id'])
                            requests.delete(url_to_delete)

                    #call the delete_intents_fun function which sends a json with ID of intent to delete to the RTR
                    '''delete_command.delete_intents_fun(df['intent_id'][ind], workflow_url)
                    # TO PUT FUNCTION FOR DELETING INTENTS IN ELASTICSEARCH HERE
                    resp = es.search(index="stored_intents", size=100, query={"match_all": {}})
                    for hit in resp['hits']['hits']:
                        if hit["_source"]['intent_id'] == df['intent_id'][ind]:
                            delete_intents_elasticsearch.delete_intents_elasticsearch_fun(elasticsearch_url,
                                                                                          hit["_source"]['id'])
                    time.sleep(1)
                    #remove this intent to be deleted from the intent store and reshuffle the intent store
                    df = df.drop(df.index[ind])
                    df = df.reset_index(drop=True)'''
            #write the modified dataframe to the intent store
            #df.to_csv('intent_store.csv', index=False)

        #repeat the process for the next intent in the intent store
        ind = ind + 1
        if ind < len(df.index) and not df.empty:
            print('resolved a conflict and continues')
            conflict_fun(df, ind, intent_host_arr, intent_dict_main, policy_dict, workflow_url, stored_intents_url,
                         elasticsearch_url)
        else:
            print('conflicts resolved')

    #if an existing intent doesn't conflict with new intent then move to the next intent in the intent store
    else:
        ind3 = ind + 1
        if ind3 < len(df.index) and not df.empty:
            conflict_fun(df, ind3, intent_host_arr, intent_dict_main, policy_dict, workflow_url,
                          stored_intents_url, elasticsearch_url)
        else:
            print('ok')
