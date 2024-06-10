import requests
import config

# the various APIs to be connected to
intents_url = config.intents_url
stored_intents_url = config.stored_intents_url
qos_intents_url = config.qos_intents_url
stored_qos_intents_url = config.stored_qos_intents_url

def extract_command_fun(command):
    command = command.split()
    #print('command: ', command)
    if 'delete' in command and 'qos' in command:
        to_delete_dict = {}
        to_delete = stored_qos_intents_url + '/' + command[3]
        requests.delete(to_delete)
        to_delete_dict['command'] = 'delete_intent'
        to_delete_dict['qos_intent_id'] = command[3]
        to_delete_dict['qos'] = command[2]
        return to_delete_dict
    elif 'delete' in command and 'qos' not in command:
        to_delete_dict = {}
        to_delete = stored_intents_url + '/' + command[2]
        requests.delete(to_delete)
        to_delete_dict['command'] = 'delete_intent'
        to_delete_dict['intent_id'] = command[2]
        return to_delete_dict
    elif 'add' in command:
        intent_dict = {}
        if command[2] == 'mit':
            intent_dict['intent_type'] = 'mitigation'
        elif command[2] == 'pre':
            intent_dict['intent_type'] = 'prevention'
        else:
            error_output = 'invalid intent_type' + command[2]
            return error_output

        if command[3] != 'ddos_ntp' and command[3] != 'ddos_dns' and command[3] != 'ddos_pfcp' and command[
            3] != 'dos_sig' and command[3] != 'api_vul':
            error_output = 'invalid threat' + command[3]
            return error_output
        else:
            intent_dict['threat'] = command[3]

        intent_dict['host'] = command[5:]
        intent_dict['duration'] = int(command[4])
        #print('intent dict b4 send: ', intent_dict)
        requests.put(intents_url, json=intent_dict)
        intent_dict['command'] = 'add_intent'
        return intent_dict
    elif 'qos' in command and 'delete' not in command:
        intent_dict = {}
        if command[2] != 'qos_ntp' and command[2] != 'qos_dns' and command[2] != 'qos_pfcp':
            error_output = 'invalid service_type' + command[2]
            return error_output
        else:
            intent_dict['intent_type'] = command[2]
        if command[3] == 'rel':
            intent_dict['name'] = 'reliability'
        elif command[3] == 'bw':
            intent_dict['name'] = 'bandwidth'
        elif command[3] == 'lat':
            intent_dict['name'] = 'latency'
        else:
            error_output = 'invalid qos name' + command[2]
            return error_output
        intent_dict['value'] = float(command[4])
        intent_dict['host'] = command[5:]
        #print('intent dict b4 send: ', intent_dict)
        requests.put(qos_intents_url, json=intent_dict)
        intent_dict['service_type'] = intent_dict['intent_type']
        del intent_dict['intent_type']
        intent_dict['command'] = 'add_qos_intent'
        print(intent_dict)
        return intent_dict
    else:
        return 'invalid command'