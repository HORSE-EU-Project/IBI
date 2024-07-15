import config
#parameters = config.parameters

#import yaml
#with open('config.yml') as f:
#    parameters = yaml.safe_load(f)
    #config = yaml.safe_load(f)

#print(list(parameters['hosts'].values()))

#mitigation_host = 'gnb'
#mitigation_host_ip = parameters['hosts']['r2']
#print(mitigation_host_ip)
#host = '192.168.56.26'
# list out keys and values separately
def find_interface_fun(host, mitigation_host):
    global found_mitigation_host, host_name, check_connected_hosts
    #interface_name = 'no_interface'
    #key_list = list(parameters['hosts'].keys())
    #val_list = list(config.hosts.values())
    key_list = list(config.hosts.keys())
    if host not in key_list:
        #print('host not in topology')
        return ('host not in topology')
    elif host in key_list:
        # list out keys and values separately
        #key_list = list(config.hosts.keys())
        # print key with the specific value
        #position = val_list.index(host)
        #host_name = key_list[position]
        host_name = host
        #print(host_name)
        #links = parameters['links']
        links = config.links
        #print(len(links))
        checked_hosts = []
        #found_mitigation_host = 0
        found_interface = []
        def check_connected_hosts(host_name):
            #print('found initial: ', found_mitigation_host)
            checked_hosts.append(host_name)
            #print('host name: ', host_name)
            #interface_name = 'no_interface'
            connected_hosts = []
            for i in range(len(links)):
                if links[i]['a_node'] == host_name:
                    connect = links[i]['z_node']
                    connected_hosts.append(connect)
                elif links[i]['z_node'] == host_name:
                    connect = links[i]['a_node']
                    connected_hosts.append(connect)
            #print('connected hosts: ', connected_hosts)

            #return connected_hosts
        #connected_hosts = check_connected_hosts(host_name)
            #found_mitigation_host = 0
            #checked_hosts = []
            for j in range(len(connected_hosts)):
                #print('checked hosts: ', checked_hosts)
                if connected_hosts[j] == mitigation_host and connected_hosts[j] not in checked_hosts:
                    #found_mitigation_host += 1
                    #print('connected h: ', connected_hosts[j])
                    for k in range(len(links)):
                        #print('anode: ', links[k]['a_node'])
                        #print('znode: ', links[k]['z_node'])
                        if links[k]['a_node'] == host_name and links[k]['z_node'] == connected_hosts[j]:
                            #print('yes it is')
                            interface_name = links[k]['z_int']
                            found_interface.append(interface_name)
                            #print('interface name: ', interface_name)
                            #print('found: ', found_mitigation_host)
                        elif links[k]['z_node'] == host_name and links[k]['a_node'] == connected_hosts[j]:
                            interface_name = links[k]['a_int']
                            found_interface.append(interface_name)
                            #print('yes it is')
                            #print('interface name: ', interface_name)
                            #print('found: ', found_mitigation_host)
                            #exit()
                elif connected_hosts[j] != mitigation_host and connected_hosts[j] not in checked_hosts:
                    #checked_hosts.append(connected_hosts[j])
                    check_connected_hosts(connected_hosts[j])
                #print('found after: ', found_mitigation_host)
                #if found_mitigation_host == 0:
                #    print('interface not found')
            #print('interface name after for loop: ', interface_name)
            #print('found interface: ', found_interface)
            if len(found_interface) > 0:
                return found_interface[0]
        #print('interface name outside function: ', interface_name)
        #print('interface name outside function: ', check_connected_hosts(host_name))
    return check_connected_hosts(host_name)

    #return interface_name

#xy = find_interface_fun('gnb', 'dns_c8')
#print('interface is finally: ', xy)
#xy = find_interface_fun('dns_c8', 'gnb')
#print('interface is finally: ', xy)

#print(xy)
'''def find_interface_fun(host, mitigation_host):
    global found_mitigation_host, host_name, check_connected_hosts
    #interface_name = 'no_interface'
    #val_list = list(parameters['hosts'].values())
    val_list = list(config.hosts.values())
    if host not in val_list:
        #print('host not in topology')
        return ('host not in topology')
    elif host in val_list:
        # list out keys and values separately
        key_list = list(config.hosts.keys())
        # print key with the specific value
        position = val_list.index(host)
        host_name = key_list[position]
        #print(host_name)
        links = config.links
        #print(len(links))
        checked_hosts = []
        #found_mitigation_host = 0
        found_interface = []
        def check_connected_hosts(host_name):
            #print('found initial: ', found_mitigation_host)
            checked_hosts.append(host_name)
            #print('host name: ', host_name)
            #interface_name = 'no_interface'
            connected_hosts = []
            for i in range(len(links)):
                if links[i]['a_node'] == host_name:
                    connect = links[i]['z_node']
                    connected_hosts.append(connect)
                elif links[i]['z_node'] == host_name:
                    connect = links[i]['a_node']
                    connected_hosts.append(connect)
            #print('connected hosts: ', connected_hosts)

            #return connected_hosts
        #connected_hosts = check_connected_hosts(host_name)
            #found_mitigation_host = 0
            #checked_hosts = []
            for j in range(len(connected_hosts)):
                #print('checked hosts: ', checked_hosts)
                if connected_hosts[j] == mitigation_host and connected_hosts[j] not in checked_hosts:
                    #found_mitigation_host += 1
                    #print('connected h: ', connected_hosts[j])
                    for k in range(len(links)):
                        #print('anode: ', links[k]['a_node'])
                        #print('znode: ', links[k]['z_node'])
                        if links[k]['a_node'] == host_name and links[k]['z_node'] == connected_hosts[j]:
                            #print('yes it is')
                            interface_name = links[k]['z_int']
                            found_interface.append(interface_name)
                            #print('interface name: ', interface_name)
                            #print('found: ', found_mitigation_host)
                        elif links[k]['z_node'] == host_name and links[k]['a_node'] == connected_hosts[j]:
                            interface_name = links[k]['a_int']
                            found_interface.append(interface_name)
                            #print('yes it is')
                            #print('interface name: ', interface_name)
                            #print('found: ', found_mitigation_host)
                            #exit()
                elif connected_hosts[j] != mitigation_host and connected_hosts[j] not in checked_hosts:
                    #checked_hosts.append(connected_hosts[j])
                    check_connected_hosts(connected_hosts[j])
                #print('found after: ', found_mitigation_host)
                #if found_mitigation_host == 0:
                #    print('interface not found')
            #print('interface name after for loop: ', interface_name)
            #print('found interface: ', found_interface)
            if len(found_interface) > 0:
                return found_interface[0]
        #print('interface name outside function: ', interface_name)
        #print('interface name outside function: ', check_connected_hosts(host_name))
    return check_connected_hosts(host_name)

    #return interface_name

#xy = find_interface_fun(host)
#print('interface is finally: ', xy)

#print(xy)'''