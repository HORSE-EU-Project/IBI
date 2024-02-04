import pandas as pd
import sys
import delete_command

#IP address of the machine on which the IBI is running
#ip = sys.argv[1]
#ip = "192.168.56.1"
#workflow_url = "http://" + ip + ":7777/workflows"

#function for deleting intents
def select_delete_fun(to_delete, ip):
    workflow_url = "http://" + ip + ":7777/workflows"
    print('to delete intent')
    df = pd.read_csv('intent_store.csv')
    #join the parameters of the desired intent to be deleted as string
    selected_delete_string = to_delete['intent_type'] + ' ' + to_delete['threat'] + ' ' + str(to_delete['host']) \
                            + ' ' + to_delete['action'] + ' ' + str(to_delete['time_frame']) + ' ' + to_delete['intent_id']

    for ind in range(len(df.index)):
        print('ind: ', ind)
        if ind < len(df.index) and not df.empty:
            #join the parameters of each of the intents in the store as string
            delete_string = df['intent_type'][ind] + ' ' + df['threat'][ind] + ' ' + str(df['host'][ind]) \
                            + ' ' + df['action'][ind] + ' ' + str(df['time_frame'][ind]) + ' ' + df['intent_id'][ind]
            print('delete string: ', delete_string)
            #if any joined string of parameters of intent corresponds with the string of intent to be deleted
            #then that intent would be deleted
            if delete_string == selected_delete_string:
                #call the delete_intents_fun function which sends a json with ID of intent to delete to the RTR
                delete_command.delete_intents_fun(df['intent_id'][ind], workflow_url)

                # TO PUT FUNCTION FOR DELETING INTENTS IN ELASTICSEARCH HERE

                # remove this intent to be deleted from the local intent store and reshuffle the intent store
                df = df.drop(df.index[ind])
                df = df.reset_index(drop=True)
                # write the modified dataframe to the local intent store
                df.to_csv('intent_store.csv', index=False)

#select_delete_fun()
