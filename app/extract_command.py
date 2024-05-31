import requests
import config

# the various APIs to be connected to
intents_url = config.intents_url
stored_intents_url = config.stored_intents_url

def extract_command_fun(command):
    command = command.split()
    #print('command: ', command)
    if 'delete' in command:
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
    else:
        return 'invalid command'