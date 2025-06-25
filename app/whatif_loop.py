from database import es_client as es
import time
import random
import string
import pandas as pd
import delete_intents_elasticsearch
import config
import get_intents_script
port = config.port
elastic_host = config.elastic_host
elastic_port = config.elastic_port
parameters = config.parameters
workflow_url = config.workflow_url
stored_qos_intents_url = config.stored_qos_intents_url


def to_send_DT(what_if_question):
    # what to send to impact DT
    # newly added
    prevention_element = {}
    prevention_element['node'] = what_if_question["prevention_host"]
    prevention_element['interface'] = what_if_question["prevention_interface"]
    #prevention_element['ref'] = what_if_question["prevention_host"] + '_' + what_if_question["prevention_interface"]
    prevention_element['network'] = "*"
    prevention_element['ref'] = prevention_element['node'] + '_' + prevention_element['interface']

    action = {}
    action['type'] = what_if_question['action']
    action['value'] = ''
    action['unit'] = ''
    action['duration'] = str(what_if_question['duration'])
    if what_if_question['action'] == 'rate_limiting':
        action['value'] = config.rate_req
        action['unit'] = 'requests-per-second'

    attacked_element = {}
    attacked_element['node'] = what_if_question["host"]
    attacked_element['interface'] = what_if_question["attacked_interface"]

    whatif_question_send = {}
    what = {}
    KPIs = {}
    iff = {}
    whatif_question_send['id'] = what_if_question['id']
    whatif_question_send['topology_name'] = 'horse_ddos'
    whatif_question_send['attack'] = what_if_question['threat']
    KPIs['element'] = attacked_element
    KPIs['metric'] = what_if_question['kpi_measured']
    what['KPIs'] = KPIs
    whatif_question_send['what_condition'] = what
    iff['action'] = action
    iff['element'] = prevention_element
    whatif_question_send['if_condition'] = iff

    return whatif_question_send

def whatif_send_fun(policy_dict, whatif_send_url):
    sent_whatif = []
    # empty dict containing the elements of the what-if question which are the matched policy attributes
    for i in range(len(policy_dict['host'])):
        whatif_question = {}
        id_digits = 9
        whatif_id = ''.join(random.choices(string.ascii_uppercase +
                                           string.digits, k=id_digits))
        print('intent type is prevention, sending what-if question')
        whatif_question['command'] = 'send_what_if'
        whatif_question['intent_type'] = policy_dict['intent_type']
        whatif_question['threat'] = policy_dict['threat']
        #whatif_question['host'] = list(policy_dict['host'][i].split(" "))
        whatif_question['host'] = policy_dict['host'][i]
        whatif_question['action'] = policy_dict['action']
        whatif_question['duration'] = str(policy_dict['duration'])
        whatif_question['id'] = whatif_id
        whatif_question['kpi_measured'] = policy_dict['kpi_measured']
        whatif_question['prevention_host'] = policy_dict['prevention_host']
        whatif_question['prevention_interface'] = policy_dict["prevention_interface"][i]
        whatif_question['attacked_interface'] = policy_dict["attacked_interface"][i]

        #whatif_question['prevention_host'] = list(policy_dict['prevention_host'][i].split(" "))
        #whatif_question['interface'] = policy_dict['interface'][i]
        #whatif_question['host_references'] = policy_dict['host_references'][i]



        intent_index = es.exists(index="awaiting_intents", id=1)
        l = len(sent_whatif)
        if l != 0 and whatif_question != sent_whatif[l - 1]:
            sent_whatif.append(whatif_question)
            if intent_index == True:
                resp1 = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
                total = resp1['hits']['total']['value']
                id = total + 1
                es.index(index="awaiting_intents", id=id, document=whatif_question)
            else:
                es.index(index="awaiting_intents", id=1, document=whatif_question)
            # send what-if question to the what_if_send_url
            send_workflows.send_workflow_fun(whatif_send_url, to_send_DT(whatif_question))
        elif l == 0:
            sent_whatif.append(whatif_question)
            if intent_index == True:
                resp1 = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
                total = resp1['hits']['total']['value']
                id = total + 1
                es.index(index="awaiting_intents", id=id, document=whatif_question)
            else:
                es.index(index="awaiting_intents", id=1, document=whatif_question)
            # send what-if question to the what_if_send_url
            send_workflows.send_workflow_fun(whatif_send_url, to_send_DT(whatif_question))
        time.sleep(1)
    #return whatif_question


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
                send_workflows.send_workflow_fun(whatif_send_url, to_send_DT(whatif_question))
        time.sleep(60)

#when a what-if answer is received from the SAN
#the IBI proceeds with the intent if the response from the SAN is acceptable
def whatif_receive_fun(whatif_receive):
    global what_if_response
    stored_qos_intents_arr = get_intents_script.get_intent_fun(stored_qos_intents_url)
    bandwidth_unit_dict = {'bps': 1, 'kbps': 10^3, 'mbps': 10^6, 'gbps': 10^9}
    latency_unit_dict = {'s': 1, 'ms': 10^(-3), 'μs': 10^(-6)}
    reliability_unit_dict = {'1': 1, '%': 100}
    reject_whatif = 0
    attacked_host = whatif_receive.what['KPIs']['element']['node']
    kpi_measured = whatif_receive.what['KPIs']['metric']
    value = whatif_receive.what['KPIs']['result']['value']
    unit = whatif_receive.what['KPIs']['result']['unit']

    for i in range(len(stored_qos_intents_arr)):
        #for j in range(len(whatif_receive.host)):
        if (attacked_host == stored_qos_intents_arr[i]['host'] and
                stored_qos_intents_arr[i]['name'] == kpi_measured):
                #and \ stored_qos_intents_arr[i]['intent_type'] == 'qos_ntp'):
            print('conflict with qos intent')
            #real_kpi_val = whatif_receive['value'] * whatif_receive['']
            if (kpi_measured == 'bandwidth'):
                dict_key_list = list(bandwidth_unit_dict.keys())
                for key in dict_key_list:
                    if (key == unit):
                        whatif_kpi_val = float(value) * bandwidth_unit_dict[key]
                        qos_kpi_val = stored_qos_intents_arr[i]['value'] * bandwidth_unit_dict[key]
                        if qos_kpi_val > whatif_kpi_val:
                            #what_if_response = 'ok'
                            reject_whatif += 1
            elif (kpi_measured == 'latency'):
                dict_key_list = list(latency_unit_dict.keys())
                for key in dict_key_list:
                    if (key == unit):
                        whatif_kpi_val = float(value) * latency_unit_dict[key]
                        qos_kpi_val = stored_qos_intents_arr[i]['value'] * latency_unit_dict[key]
                        if qos_kpi_val < whatif_kpi_val:
                            #what_if_response = 'ok'
                            reject_whatif += 1
            elif (kpi_measured == 'reliability'):
                dict_key_list = list(reliability_unit_dict.keys())
                for key in dict_key_list:
                    if (key == unit):
                        whatif_kpi_val = float(value) * reliability_unit_dict[key]
                        qos_kpi_val = stored_qos_intents_arr[i]['value'] * reliability_unit_dict[key]
                        if qos_kpi_val > whatif_kpi_val:
                            #what_if_response = 'ok'
                            reject_whatif += 1

    if reject_whatif == 0:
        what_if_response = 'ok'
    else:
        what_if_response = 'reject'

    import policy_configurator
    stored_intents_url = config.stored_intents_url
    whatif_answer = {}
    if what_if_response == 'ok':
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
                if whatif_question['id'] == whatif_receive.id:
                    # and \ whatif_question['threat'] == whatif_receive.threat and \
                    #    whatif_question['host'] == whatif_receive.host
                    whatif_answer['command'] = 'add'
                    whatif_answer['intent_type'] = whatif_question['intent_type']
                    whatif_answer['threat'] = whatif_question['threat']
                    whatif_answer['host'] = list(whatif_question['host'].split(" "))
                    whatif_answer['action'] = whatif_question['action']
                    whatif_answer['duration'] = whatif_question['duration']
                    whatif_answer['id'] = whatif_receive.id
                    whatif_answer['what_if_response'] = what_if_response
                    df_policy = pd.read_csv(config.policy_store_directory)
                    for ind in df_policy.index:
                        if df_policy['action'][ind] == whatif_answer['action']:
                            whatif_answer['priority'] = df_policy['priority'][ind]
                    policy_configurator.policy_configurator_fun_2(workflow_url, stored_intents_url, whatif_answer)
    else:
        print('not proceeding with intent')
    resp = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
    for ind in range(len(resp['hits']['hits'])):
        hit1 = resp['hits']['hits'][ind]['_source']
        if hit1['intent_type'] == whatif_answer['intent_type'] and hit1['threat'] == whatif_answer['threat'] and \
                str(hit1['host']) == str(whatif_answer['host'][0]) and hit1['action'] == whatif_answer['action'] and \
                str(hit1['duration']) == str(whatif_answer['duration']) and hit1['id'] == whatif_answer['id']:
            delete_intents_elasticsearch.delete_intents_elasticsearch_fun(resp['hits']['hits'][ind]['_id'], "awaiting_intents")

def del_whatif_fun(policy_dict):
    int_ind = False
    for i in list(range(100)):
        intent_index = es.exists(index="awaiting_intents", id=str(i))
        if intent_index == True:
            int_ind = True
    if int_ind == True:
        resp = es.search(index="awaiting_intents", size=100, query={"match_all": {}})
        for ind in range(len(resp['hits']['hits'])):
            hit1 = resp['hits']['hits'][ind]['_source']
            if hit1['threat'] == policy_dict['threat'] and hit1['host'] == policy_dict['host']:
                delete_intents_elasticsearch.delete_intents_elasticsearch_fun(resp['hits']['hits'][ind]['_id'], "awaiting_intents")
