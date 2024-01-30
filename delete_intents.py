from __future__ import print_function, unicode_literals
from PyInquirer import style_from_dict, Token, prompt
import pandas as pd
import sys
import delete_command

#IP address of the machine on which the IBI is running
ip = sys.argv[1]
#ip = "192.168.56.1"
workflow_url = "http://" + ip + ":7778/workflows"

#function for deleting intents
def select_delete_fun():
    style = style_from_dict({
            Token.QuestionMark: '#E91E63 bold',
            Token.Selected: '#673AB7 bold',
            Token.Instruction: '',  # default
            Token.Answer: '#2196f3 bold',
            Token.Question: '',
        })
    print('to delete intent')
    df = pd.read_csv('intent_store.csv')
    #array of intent_ids
    intent_id_list = []
    #array of the whole intents from which to choose which one to delete
    intent_choices_delete = []

    for ind in df.index:
        #add the IDs of the whole intents in the intent store to intent_id_list
        intent_id_list.append(df['intent_id'][ind])
        empty_dict = {}
        # join the intent parameters as string, put inside a dictionary and add to intent_choices_delete array
        delete_string = df['intent_type'][ind] + ' ' + df['threat'][ind] + ' ' + str(df['host'][ind]) \
                        + ' ' + df['action'][ind] + ' ' + str(df['time_frame'][ind]) + ' ' + df['intent_id'][ind]
        empty_dict['name'] = delete_string

        intent_choices_delete.append(empty_dict)

    #prompts on the terminal for one to select which intent(s) to delete
    question_delete = [

        {
            'type': 'checkbox',
            'qmark': '',
            'name': 'delete',
            'message': 'Select Intent(s) to Delete: ',
            'choices': intent_choices_delete

        }

    ]
    answer_delete = prompt(question_delete, style=style)
    #answer_delete_arr is an array of selected intents to delete
    answer_delete_arr = answer_delete['delete']

    for i in range(len(answer_delete_arr)):
        for ind in range(len(df.index)):
            if ind < len(df.index) and not df.empty:
                #join the intents as string again
                delete_string = df['intent_type'][ind] + ' ' + df['threat'][ind] + ' ' + str(df['host'][ind]) \
                                + ' ' + df['action'][ind] + ' ' + str(df['time_frame'][ind]) + ' ' + df['intent_id'][ind]

                #if any joined string of intents corresponds with any string in answer_delete_arr
                #then that intent would be deleted
                if delete_string == answer_delete_arr[i]:
                    #call the delete_intents_fun function which sends a json with ID of intent to delete to the RTR
                    delete_command.delete_intents_fun(df['intent_id'][ind], workflow_url)
                    # remove this intent to be deleted from the intent store and reshuffle the intent store
                    df = df.drop(df.index[ind])
                    df = df.reset_index(drop=True)
                    # write the modified dataframe to the intent store
                    df.to_csv('intent_store.csv', index=False)

select_delete_fun()