import time
import pandas as pd
import os
import csv
import random
import string
import conflict_resolution
import get_intents
import send_workflows
import sys


def intent_manager_fun(intent_dict_main, workflow_url):
    #columns to be used while writing the intents into the intent store
    columns = ['intent_id', 'intent_type', 'threat', 'host', 'action', 'time_frame', 'priority']
    intent_store = 'intent_store.csv'
    #set whether to proceed with the intents as false first
    to_proceed = False
    #create the empty intent store
    if os.path.exists(intent_store) == False:
        with open(intent_store, 'a') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=columns)
            writer.writeheader()
    #intent_dict_main is the json of the intent received from the DTE, extract the hosts in the intent_dict_main
    intent_host_arr = intent_dict_main['host']

    global policy_dict, df
    #create an empty policy dictionary where to store the matched policy at first
    policy_dict = {}
    #the policy store in dataframe
    df_policy = pd.read_csv('policy_store.csv')

    #populate the policy dictionary
    #it would contain the intent type, threat, host, duration, action to take and priority value of policy
    policy_dict['intent_type'] = intent_dict_main['intent_type']
    policy_dict['threat'] = intent_dict_main['threat']
    policy_dict['host'] = intent_dict_main['host']
    policy_dict['time_frame'] = intent_dict_main['time_frame']
    #empty action list to store all actions for a particular threat and intent_type
    action_list = []
    #add the action and priority to the policy dict, for now, a corresponding action to an intent is selected randomly
    #the higher the priority value of a policy, the less the preference for that policy
    #the policy with the highest preference has priority value of 1
    if intent_dict_main['intent_type'] == 'mitigation':
        if intent_dict_main['threat'] == 'ddos':
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'mitigation' and df_policy['threat'][ind] == 'ddos':
                    action_list.append(df_policy['action'][ind])
            policy_dict['action'] = random.choice(action_list)
            for ind in df_policy.index:
                if df_policy['action'][ind] == policy_dict['action']:
                    policy_dict['priority'] = df_policy['priority'][ind]
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
        if intent_dict_main['threat'] == 'ddos':
            for ind in df_policy.index:
                if df_policy['intent_type'][ind] == 'prevention' and df_policy['threat'][ind] == 'ddos':
                    action_list.append(df_policy['action'][ind])
            policy_dict['action'] = random.choice(action_list)
            for ind in df_policy.index:
                if df_policy['action'][ind] == policy_dict['action']:
                    policy_dict['priority'] = df_policy['priority'][ind]
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


    #empty dict containing the elements of the what-if question which are the matched policy attributes
    whatif_question = {}

    # check whether intent_type is mitigation or prevention
    # if mitigation then proceed, but if prevention then send what-if question to the SAN
    if policy_dict['intent_type'] == 'mitigation':
        to_proceed = True
    elif policy_dict['intent_type'] == 'prevention':
        print('intent type is prevention, sending what-if question')
        whatif_question['command'] = 'send_what_if'
        whatif_question['intent_type'] = policy_dict['intent_type']
        whatif_question['threat'] = policy_dict['threat']
        whatif_question['host'] = policy_dict['host']
        whatif_question['action'] = policy_dict['action']
        whatif_question['time_frame'] = str(policy_dict['time_frame'])
        #send what-if question to the what_if_send_url
        send_workflows.send_workflow_fun(whatif_send_url, whatif_question)
        time.sleep(60)
        #get what-if answer from the what_if_receive_url
        whatif_answer = get_intents.get_intent_fun(whatif_receive_url)
        if whatif_answer['what_if_response'] == 'ok':
            to_proceed = True
        else:
            print('not proceeding with intent')

    #if intent type is mitigation or intent type is prevention with what if response ok, then proceed
    if to_proceed == True:
        print('proceeding with intent')

        #evaluate whether there is conflict of intents and resolve it with the conflict resolution component
        if os.path.exists(intent_store) == True:
            df = pd.read_csv(intent_store)
            if not df.empty:
                conflict_resolution.conflict_fun(df, 0, intent_host_arr, intent_dict_main, policy_dict, workflow_url)

        #if a host has an intent in the intent store, and still receives a new intent with the priority value of the policy
        #higher than or equal to the one of the existing intent, then the host is stored inside the array - host_existing
        host_existing = []
        #the id of each intent would have 7 digits
        id_digits = 7
        if os.path.exists(intent_store) == True:
            #open the intent store file and add column labels to it
            with open(intent_store, 'a') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=columns)
                df = pd.read_csv(intent_store)
                for j in range(len(intent_host_arr)):
                    #if no intent has been entered into the intent store, write the new intent inside it
                    if df.empty:
                        intent_id = ''.join(random.choices(string.ascii_uppercase +
                                                     string.digits, k=id_digits))
                        base_data = {'intent_id': str(intent_id),
                                     'intent_type': policy_dict['intent_type'],
                                     'threat': policy_dict['threat'],
                                     'host': intent_host_arr[j],
                                     'action': policy_dict['action'],
                                     'time_frame': policy_dict['time_frame'],
                                     'priority': policy_dict['priority']
                                     }
                        writer.writerow(base_data)
                    else:
                        exist = 0
                        #if there is an existing intent for a host, but the priority value of the new intent coming in is higher
                        #than or equal to that of the existing intent, then no action is taken, the host is added to the
                        #host_existing array, else write the new intent into the intent store
                        for ind in df.index:
                            if df['host'][ind] == intent_host_arr[j] and df['threat'][ind] == intent_dict_main['threat'] and ind < len(df.index):
                                if policy_dict['priority'] >= df['priority'][ind]:
                                    exist += 1
                                    policy_dict['threat'] = df['threat'][ind]
                                    policy_dict['host'] = intent_host_arr
                                    host_existing.append(intent_host_arr[j])
                                    policy_dict['time_frame'] = df['time_frame'][ind]

                        #write new intent into the intent store
                        if exist == 0:
                            intent_id = ''.join(random.choices(string.ascii_uppercase +
                                                               string.digits, k=id_digits))
                            base_data = {'intent_id': str(intent_id),
                                         'intent_type': policy_dict['intent_type'],
                                         'threat': policy_dict['threat'],
                                         'host': intent_host_arr[j],
                                         'action': policy_dict['action'],
                                         'time_frame': policy_dict['time_frame'],
                                         'priority': policy_dict['priority']
                                         }
                            writer.writerow(base_data)


        #delete the priority value of the policy cos it's not needed while sending it out
        del policy_dict["priority"]
        #policy arr stores the policy or policies that would be sent
        policy_arr = []
        df = pd.read_csv(intent_store)
        for ind in df.index:
            for ip in policy_dict['host']:
                #each policy to be sent as workflow is referred to as policy_send
                policy_send = {}
                policy_send['command'] = 'enter_intent'
                policy_send['intent_type'] = policy_dict['intent_type']
                policy_send['threat'] = policy_dict['threat']
                policy_send['host'] = ip
                policy_send['action'] = policy_dict['action']
                policy_send['time_frame'] = str(policy_dict['time_frame'])

                #now, the intent(s) have been compiled into policies and written into the intent store
                #however, they have not been sent to the RTR
                #if the parameters of a policy to be sent match the paremeters of a policy that has been written in the intent store
                #and the host is not inside the host_exisiting array which implies the policy is a new one
                #then assign the intent_id to the policy cos it must go out with an id
                exist_in_host_existing = 0
                if policy_send['intent_type'] == df['intent_type'][ind] and policy_send['threat'] == df['threat'][ind] and \
                        policy_send['host'] == df['host'][ind] and policy_send['action'] == df['action'][ind] and \
                        policy_send['time_frame'] == str(df['time_frame'][ind]):
                    for i in range(len(host_existing)):
                        if policy_send['host'] == host_existing[i]:
                            exist_in_host_existing += 1
                    if exist_in_host_existing == 0:
                        policy_send['intent_id'] = df['intent_id'][ind]

                #add the policy to be sent into the policy array cos it meets the criteria above
                if 'intent_id' in policy_send.keys():
                    policy_arr.append(policy_send)

        #send the policy or policies inside the policy array as workflow to the RTR
        for i in range(len(policy_arr)):
            send_workflows.send_workflow_fun(workflow_url, policy_arr[i])
            time.sleep(1)

#stores the intents retrieved from the intent api
retrieved_intents_arr = []
print('intent manager started - waiting for intent')
#IP address of the machine on which the IBI is running
ip = sys.argv[1]
#ip = "192.168.56.1"
#the various APIs to be connected to
intents_url = "http://" + ip + ":7777/intents"
workflow_url = "http://" + ip + ":7778/workflows"
whatif_send_url = "http://" + ip + ":7779/workflows"
whatif_receive_url = "http://" + ip + ":7780/workflows"
#intents_url = "http://192.168.56.1:7777/intents"
#workflow_url = "http://192.168.56.1:7778/workflows"

while True:
    #get the intent from the intent api
    intent_dict_main = get_intents.get_intent_fun(intents_url)

    #if new intent got from the intent api is not the same with the last intent stored in retrieved_intents_arr
    #or if retrieved_intents_arr is empty, then call the intent manager function - intent_manager_fun
    if intent_dict_main['intent_type'] != '':
        l = len(retrieved_intents_arr)
        if l != 0:
            if retrieved_intents_arr[l-1] != intent_dict_main:
                retrieved_intents_arr.append(intent_dict_main)
                intent_manager_fun(intent_dict_main, workflow_url)
        else:
            retrieved_intents_arr.append(intent_dict_main)
            intent_manager_fun(intent_dict_main, workflow_url)
    #repeat every five seconds
    time.sleep(5)


