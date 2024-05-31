import requests

#the function that sends the intents to the stored intents api
def store_intent_fun(stored_intents_url, intent):
    requests.post(stored_intents_url, json=intent)
    #print(response.json())
    #print('stored intent: ', intent)