---
mode: agent
---
- I would like to developt an intent-based network system building upon the MAPE-K approach.
- The system receives intents and state of the network though API requests from a module called DTE
- The Knowledge base is an in memory databas that will be persisted in ElasticSearch Later
- The system should have an GUI in form of a dashboard to display the intents, threats and their state (Like mitigated, under mitigation and other states defined in the file app.models.core_models)
- this system (the IBN System) should infer the desired state of the network from the intents, mitigating the reported attacks and propose actions to be applied in the network
  - mitigation intents generate actions that should be evaluated agains a module called CAS and applied in the network
  - prevention intents generate actions that should be evaluated with a Network Digital Twin accessible via an HTTP API and that produces asynchrounous answers, if the action produces results above a certais threshould, it should evaluate with the CAS and and send the actions to the RTR via HTTP API to apply it on the network.