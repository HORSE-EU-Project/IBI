import time
import pandas as pd
import random
import string
import conflict_resolution
import send_workflows
import store_intent
from elasticsearch import Elasticsearch
import whatif_loop
import config
import get_intents_script

def policy_configurator_fun(intent_dict_main, workflow_url, whatif_send_url,
                       stored_intents_url, elasticsearch_url, access_token):
    global policy_dict
    stored_qos_intents_url = config.stored_qos_intents_url
    #create an empty policy dictionary where to store the matched policy at first
    policy_dict = {}
    #the policy store in dataframe
    df_policy = pd.read_csv(config.policy_store_directory)

    #populate the policy dictionary
    #it would contain the intent type, threat, host, duration, action to take and priority value of policy
    policy_dict['intent_type'] = intent_dict_main['intent_type']
    policy_dict['threat'] = intent_dict_main['threat']
    policy_dict['host'] = intent_dict_main['host']
    policy_dict['duration'] = intent_dict_main['duration']
    #empty action list to store all actions for a particular threat and intent_type
    action_list = []
    priority_list = []
    #add the action and priority to the policy dict
    #the higher the priority value of a policy, the less the preference for that policy
    #the policy with the highest preference has priority value of 1
    stored_qos_intents_arr = get_intents_script.get_intent_fun(stored_qos_intents_url)

    if intent_dict_main['intent_type'] == 'mitigation':
        if intent_dict_main['threat'] == 'ddos_ntp':
            problem_constraints = []
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_ntp':
                    for i in range(len(stored_qos_intents_arr)):
                        for j in range(len(policy_dict['host'])):
                            #print(policy_dict['host'][j], stored_qos_intents_arr[i]['host'],
                            #        stored_qos_intents_arr[i]['name'], df_policy['constraint'][ind])
                            if policy_dict['host'][j] == stored_qos_intents_arr[i]['host'] and \
                                    stored_qos_intents_arr[i]['name'] == df_policy['constraint'][ind] and \
                                    stored_qos_intents_arr[i]['intent_type'] == 'qos_ntp':
                                print('conflict with qos intent')
                                problem_constraints.append(df_policy['constraint'][ind])
                    #print('problem constraints: ', problem_constraints)
            for i in range(len(problem_constraints)):
                df_policy = df_policy.drop(df_policy[df_policy['constraint'] == problem_constraints[i]].index)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_ntp':
                    priority_list.append(df_policy['priority'][ind])
                    #print('priority list: ', priority_list)
            chosen_priority = min(priority_list)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_ntp' \
                        and df_policy['priority'][ind] == chosen_priority:
                    policy_dict['priority'] = df_policy['priority'][ind]
                    policy_dict['action'] = df_policy['action'][ind]

        elif intent_dict_main['threat'] == 'ddos_dns':
            problem_constraints = []
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_dns':
                    for i in range(len(stored_qos_intents_arr)):
                        for j in range(len(policy_dict['host'])):
                            # print(policy_dict['host'][j], stored_qos_intents_arr[i]['host'],
                            #        stored_qos_intents_arr[i]['name'], df_policy['constraint'][ind])
                            if policy_dict['host'][j] == stored_qos_intents_arr[i]['host'] and \
                                    stored_qos_intents_arr[i]['name'] == df_policy['constraint'][ind] and \
                                    stored_qos_intents_arr[i]['intent_type'] == 'qos_dns':
                                print('conflict with qos intent')
                                problem_constraints.append(df_policy['constraint'][ind])
                    # print('problem constraints: ', problem_constraints)
            for i in range(len(problem_constraints)):
                df_policy = df_policy.drop(df_policy[df_policy['constraint'] == problem_constraints[i]].index)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_dns':
                    priority_list.append(df_policy['priority'][ind])
                    # print('priority list: ', priority_list)
            chosen_priority = min(priority_list)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_dns' \
                        and df_policy['priority'][ind] == chosen_priority:
                    policy_dict['priority'] = df_policy['priority'][ind]
                    policy_dict['action'] = df_policy['action'][ind]

        elif intent_dict_main['threat'] == 'ddos_pfcp':
            problem_constraints = []
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_pfcp':
                    for i in range(len(stored_qos_intents_arr)):
                        for j in range(len(policy_dict['host'])):
                            # print(policy_dict['host'][j], stored_qos_intents_arr[i]['host'],
                            #        stored_qos_intents_arr[i]['name'], df_policy['constraint'][ind])
                            if policy_dict['host'][j] == stored_qos_intents_arr[i]['host'] and \
                                    stored_qos_intents_arr[i]['name'] == df_policy['constraint'][ind] and \
                                    stored_qos_intents_arr[i]['intent_type'] == 'qos_pfcp':
                                print('conflict with qos intent')
                                problem_constraints.append(df_policy['constraint'][ind])
                    # print('problem constraints: ', problem_constraints)
            for i in range(len(problem_constraints)):
                df_policy = df_policy.drop(df_policy[df_policy['constraint'] == problem_constraints[i]].index)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_pfcp':
                    priority_list.append(df_policy['priority'][ind])
                    # print('priority list: ', priority_list)
            chosen_priority = min(priority_list)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos_pfcp' \
                        and df_policy['priority'][ind] == chosen_priority:
                    policy_dict['priority'] = df_policy['priority'][ind]
                    policy_dict['action'] = df_policy['action'][ind]

        elif intent_dict_main['threat'] == 'dos_sig':
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'dos_sig':
                    action_list.append(df_policy['action'][ind])
            policy_dict['action'] = random.choice(action_list)
            for ind in df_policy.index:
                if df_policy['action'][ind] == policy_dict['action']:
                    policy_dict['priority'] = df_policy['priority'][ind]
        elif intent_dict_main['threat'] == 'api_vul':
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'api_vul':
                    action_list.append(df_policy['action'][ind])
            policy_dict['action'] = random.choice(action_list)
            for ind in df_policy.index:
                if df_policy['action'][ind] == policy_dict['action']:
                    policy_dict['priority'] = df_policy['priority'][ind]

    elif intent_dict_main['intent_type'] == 'prevention':
        if intent_dict_main['threat'] == 'ddos_ntp':
            problem_constraints = []
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_ntp':
                    for i in range(len(stored_qos_intents_arr)):
                        for j in range(len(policy_dict['host'])):
                            # print(policy_dict['host'][j], stored_qos_intents_arr[i]['host'],
                            #        stored_qos_intents_arr[i]['name'], df_policy['constraint'][ind])
                            if policy_dict['host'][j] == stored_qos_intents_arr[i]['host'] and \
                                    stored_qos_intents_arr[i]['name'] == df_policy['constraint'][ind] and \
                                    stored_qos_intents_arr[i]['intent_type'] == 'qos_ntp':
                                print('conflict with qos intent')
                                problem_constraints.append(df_policy['constraint'][ind])
                    # print('problem constraints: ', problem_constraints)
            for i in range(len(problem_constraints)):
                df_policy = df_policy.drop(df_policy[df_policy['constraint'] == problem_constraints[i]].index)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_ntp':
                    priority_list.append(df_policy['priority'][ind])
                    # print('priority list: ', priority_list)
            chosen_priority = min(priority_list)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_ntp' \
                        and df_policy['priority'][ind] == chosen_priority:
                    policy_dict['priority'] = df_policy['priority'][ind]
                    policy_dict['action'] = df_policy['action'][ind]

        elif intent_dict_main['threat'] == 'ddos_dns':
            problem_constraints = []
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_dns':
                    for i in range(len(stored_qos_intents_arr)):
                        for j in range(len(policy_dict['host'])):
                            # print(policy_dict['host'][j], stored_qos_intents_arr[i]['host'],
                            #        stored_qos_intents_arr[i]['name'], df_policy['constraint'][ind])
                            if policy_dict['host'][j] == stored_qos_intents_arr[i]['host'] and \
                                    stored_qos_intents_arr[i]['name'] == df_policy['constraint'][ind] and \
                                    stored_qos_intents_arr[i]['intent_type'] == 'qos_dns':
                                print('conflict with qos intent')
                                problem_constraints.append(df_policy['constraint'][ind])
                    # print('problem constraints: ', problem_constraints)
            for i in range(len(problem_constraints)):
                df_policy = df_policy.drop(df_policy[df_policy['constraint'] == problem_constraints[i]].index)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_dns':
                    priority_list.append(df_policy['priority'][ind])
                    # print('priority list: ', priority_list)
            chosen_priority = min(priority_list)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_dns' \
                        and df_policy['priority'][ind] == chosen_priority:
                    policy_dict['priority'] = df_policy['priority'][ind]
                    policy_dict['action'] = df_policy['action'][ind]

        elif intent_dict_main['threat'] == 'ddos_pfcp':
            problem_constraints = []
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_pfcp':
                    for i in range(len(stored_qos_intents_arr)):
                        for j in range(len(policy_dict['host'])):
                            # print(policy_dict['host'][j], stored_qos_intents_arr[i]['host'],
                            #        stored_qos_intents_arr[i]['name'], df_policy['constraint'][ind])
                            if policy_dict['host'][j] == stored_qos_intents_arr[i]['host'] and \
                                    stored_qos_intents_arr[i]['name'] == df_policy['constraint'][ind] and \
                                    stored_qos_intents_arr[i]['intent_type'] == 'qos_pfcp':
                                print('conflict with qos intent')
                                problem_constraints.append(df_policy['constraint'][ind])
                    # print('problem constraints: ', problem_constraints)
            for i in range(len(problem_constraints)):
                df_policy = df_policy.drop(df_policy[df_policy['constraint'] == problem_constraints[i]].index)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_pfcp':
                    priority_list.append(df_policy['priority'][ind])
                    # print('priority list: ', priority_list)
            chosen_priority = min(priority_list)
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos_pfcp' \
                        and df_policy['priority'][ind] == chosen_priority:
                    policy_dict['priority'] = df_policy['priority'][ind]
                    policy_dict['action'] = df_policy['action'][ind]

        elif intent_dict_main['threat'] == 'dos_sig':
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'dos_sig':
                    action_list.append(df_policy['action'][ind])
            policy_dict['action'] = random.choice(action_list)
            for ind in df_policy.index:
                if df_policy['action'][ind] == policy_dict['action']:
                    policy_dict['priority'] = df_policy['priority'][ind]
        elif intent_dict_main['threat'] == 'api_vul':
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'api_vul':
                    action_list.append(df_policy['action'][ind])
            policy_dict['action'] = random.choice(action_list)
            for ind in df_policy.index:
                if df_policy['action'][ind] == policy_dict['action']:
                    policy_dict['priority'] = df_policy['priority'][ind]

    # check whether intent_type is mitigation or prevention
    # if mitigation then proceed, but if prevention then send what-if question to the SAN
    if policy_dict['intent_type'] == 'mitigation':
        print('proceeding with intent')
        whatif_loop.del_whatif_fun(policy_dict)
        policy_configurator_fun_2(workflow_url, stored_intents_url, elasticsearch_url, policy_dict, access_token)
    elif policy_dict['intent_type'] == 'prevention':
        return whatif_loop.whatif_send_fun(policy_dict, whatif_send_url)

def policy_configurator_fun_2(workflow_url, stored_intents_url, elasticsearch_url,
                              policy_dict, access_token):
    es = Elasticsearch(elasticsearch_url)

    # extract the hosts in the policy_dict
    intent_host_arr = policy_dict['host']

    intent_index = es.exists(index="stored_intents", id="1")
    if intent_index == True:
        resp1 = es.search(index="stored_intents", size=100, query={"match_all": {}})
        total = resp1['hits']['total']['value']
        #if there are existing intents, check for conflicts
        if total >= 1:
            conflict_resolution.conflict_fun(0, policy_dict, workflow_url,
                                             stored_intents_url, elasticsearch_url)

    #if a host has an intent in the intent store, and still receives a new intent with the priority value of the policy
    #higher than or equal to the one of the existing intent, then the host is stored inside the array - host_existing
    host_existing = []
    #the id of each intent would have 7 digits
    id_digits = 7
    for j in range(len(intent_host_arr)):
        intent_id = ''.join(random.choices(string.ascii_uppercase +
                                     string.digits, k=id_digits))
        base_data = {'intent_type': policy_dict['intent_type'],
                     'threat': policy_dict['threat'],
                     'host': intent_host_arr[j],
                     'action': policy_dict['action'],
                     'duration': policy_dict['duration'],
                     'intent_id': str(intent_id),
                     'priority': str(policy_dict['priority'])
                     }

        intent_index = es.exists(index="stored_intents", id="1")
        if intent_index == True:
            resp1 = es.search(index="stored_intents", size=100, query={"match_all": {}})
            id_arr = []
            exist = 0
            for hit in resp1['hits']['hits']:
                id_arr.append(hit["_id"])
                if hit['_source']['host'] == intent_host_arr[j] and \
                        hit['_source']['threat'] == policy_dict['threat'] and \
                            int(policy_dict['priority']) >= int(hit['_source']['priority']):
                    exist += 1
                    host_existing.append(intent_host_arr[j])

            if exist == 0:
                resp1 = es.search(index="stored_intents", size=100, query={"match_all": {}})
                total = resp1['hits']['total']['value']
                id = total + 1
                es.index(index="stored_intents", id=id, document=base_data)

                # send the policies as intents to be stored on the stored_intents api
                store_intent.store_intent_fun(stored_intents_url, base_data)
                del base_data["priority"]
                base_data["command"] = 'add'
                base_data["attacked_host"] = base_data["host"]
                del base_data["host"]
                base_data["duration"] = int(base_data["duration"])
                if base_data['threat'] == 'ddos_ntp':
                    base_data["mitigation_host"] = config.ddos_ntp[base_data['action']]
                elif base_data['threat'] == 'ddos_dns':
                    base_data["mitigation_host"] = config.ddos_dns[base_data['action']]
                elif base_data['threat'] == 'ddos_pfcp':
                    base_data["mitigation_host"] = config.ddos_pfcp[base_data['action']]
                #base_data["mitigation_host"] = 'Gateway'
                #send workflows to workflow api
                send_workflows.send_workflow_fun_2(workflow_url, base_data, access_token, base_data["attacked_host"])
                time.sleep(1)
        else:
            #resp1 = es.search(index="stored_intents", size=100, query={"match_all": {}})
            #total = resp1['hits']['total']['value']
            #base_data['id'] = total + 1
            #es.index(index="stored_intents", id=base_data['id'], document=base_data)
            es.index(index="stored_intents", id=str(1), document=base_data)
            # send the policies as intents to be stored on the stored_intents api
            store_intent.store_intent_fun(stored_intents_url, base_data)
            del base_data["priority"]
            base_data["command"] = 'add'
            base_data["attacked_host"] = base_data["host"]
            del base_data["host"]
            base_data["duration"] = int(base_data["duration"])
            if base_data['threat'] == 'ddos_ntp':
                base_data["mitigation_host"] = config.ddos_ntp[base_data['action']]
            elif base_data['threat'] == 'ddos_dns':
                base_data["mitigation_host"] = config.ddos_dns[base_data['action']]
            elif base_data['threat'] == 'ddos_pfcp':
                base_data["mitigation_host"] = config.ddos_pfcp[base_data['action']]
            # base_data["mitigation_host"] = 'Gateway'
            #del base_data["id"]
            # send workflows to workflow api
            send_workflows.send_workflow_fun_2(workflow_url, base_data, access_token, base_data["attacked_host"])
            time.sleep(1)

def policy_configurator_fun_qos(policy_dict, workflow_url, stored_qos_intents_url,
                                                                elasticsearch_url):
    es = Elasticsearch(elasticsearch_url)

    # extract the hosts in the policy_dict
    intent_host_arr = policy_dict['host']

    intent_index = es.exists(index="stored_qos_intents", id="1")
    if intent_index == True:
        resp1 = es.search(index="stored_qos_intents", size=100, query={"match_all": {}})
        total = resp1['hits']['total']['value']
        #if there are existing intents, check for conflicts
        if total >= 1:
            conflict_resolution.conflict_fun(0, policy_dict, workflow_url,
                                             stored_qos_intents_url, elasticsearch_url)

    #if a host has an intent in the intent store, and still receives a new intent with the priority value of the policy
    #higher than or equal to the one of the existing intent, then the host is stored inside the array - host_existing
    host_existing = []
    #the id of each intent would have 7 digits
    id_digits = 7
    for j in range(len(intent_host_arr)):
        qos_intent_id = ''.join(random.choices(string.ascii_uppercase +
                                     string.digits, k=id_digits))
        base_data = {'intent_type': policy_dict['intent_type'],
                     'name': policy_dict['name'],
                     'value': policy_dict['value'],
                     'host': intent_host_arr[j],
                     'qos_intent_id': str(qos_intent_id),
                     }

        intent_index = es.exists(index="stored_qos_intents", id="1")
        if intent_index == True:
            resp1 = es.search(index="stored_qos_intents", size=100, query={"match_all": {}})
            id_arr = []
            exist = 0
            '''for hit in resp1['hits']['hits']:
                id_arr.append(hit["_id"])
                if hit['_source']['host'] == intent_host_arr[j] and \
                        hit['_source']['name'] == policy_dict['name'] and \
                        hit['_source']['intent_type'] == policy_dict['intent_type']:
                    exist += 1
                    host_existing.append(intent_host_arr[j])'''

            #if exist == 0:
            #    resp1 = es.search(index="stored_qos_intents", size=100, query={"match_all": {}})
            total = resp1['hits']['total']['value']
            id = total + 1
            es.index(index="stored_qos_intents", id=id, document=base_data)

            # send the policies as intents to be stored on the stored_intents api
            store_intent.store_intent_fun(stored_qos_intents_url, base_data)
            #del base_data["priority"]
            '''base_data["command"] = 'add'
            base_data["attacked_host"] = base_data["host"]
            del base_data["host"]
            if base_data['threat'] == 'ddos_ntp':
                base_data["mitigation_host"] = config.ddos_ntp[base_data['action']]
            elif base_data['threat'] == 'ddos_dns':
                base_data["mitigation_host"] = config.ddos_dns[base_data['action']]
            elif base_data['threat'] == 'ddos_pfcp':
                base_data["mitigation_host"] = config.ddos_pfcp[base_data['action']]
            #base_data["mitigation_host"] = 'Gateway'
            #send workflows to workflow api
            send_workflows.send_workflow_fun_2(workflow_url, base_data)'''
            time.sleep(1)
        else:
            #resp1 = es.search(index="stored_intents", size=100, query={"match_all": {}})
            #total = resp1['hits']['total']['value']
            #base_data['id'] = total + 1
            #es.index(index="stored_intents", id=base_data['id'], document=base_data)
            es.index(index="stored_qos_intents", id=str(1), document=base_data)
            # send the policies as intents to be stored on the stored_intents api
            store_intent.store_intent_fun(stored_qos_intents_url, base_data)
            '''del base_data["priority"]
            base_data["command"] = 'add'
            base_data["attacked_host"] = base_data["host"]
            del base_data["host"]
            if base_data['threat'] == 'ddos_ntp':
                base_data["mitigation_host"] = config.ddos_ntp[base_data['action']]
            elif base_data['threat'] == 'ddos_dns':
                base_data["mitigation_host"] = config.ddos_dns[base_data['action']]
            elif base_data['threat'] == 'ddos_pfcp':
                base_data["mitigation_host"] = config.ddos_pfcp[base_data['action']]
            # base_data["mitigation_host"] = 'Gateway'
            #del base_data["id"]
            # send workflows to workflow api
            send_workflows.send_workflow_fun_2(workflow_url, base_data)'''
            time.sleep(1)




