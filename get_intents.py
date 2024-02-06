import requests

def get_intent_fun(URL):
    r = requests.get(url = URL)

    # extracting data in json format
    data = r.json()

    #print(data)
    #return data[0]
    return data

