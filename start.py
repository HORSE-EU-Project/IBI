import subprocess
import shlex
import time
import os
import sys

#IP address of the machine on which the IBI is running
host = sys.argv[1]

#delete any old intent store whenever u start a new deployment
intent_store = 'intent_store.csv'
if (os.path.exists(intent_store) and os.path.isfile(intent_store)):
    os.remove(intent_store)

commands = (
    # Open a new terminal and create intent api
    "gnome-terminal --tab -- bash -c \"python3 create_intent_api.py " + host + "; exec bash\"",
    # Open a new terminal and create workflow api
    "gnome-terminal --tab -- bash -c \"python3 create_rtr_workflow_api.py " + host + "; exec bash\"",
    # Open a new terminal and create what-if send api
    "gnome-terminal --tab -- bash -c \"python3 create_whatif_send_api.py " + host + "; exec bash\"",
    # Open a new terminal and create what-if receive api
    "gnome-terminal --tab -- bash -c \"python3 create_whatif_receive_api.py " + host + "; exec bash\"",
    # Open a new terminal through which intents could be deleted
    "gnome-terminal --tab -- bash",
    # Open a new terminal and run intent manager
    "gnome-terminal --tab -- bash -c \"python3 intent_manager.py " + host + "; exec bash\"",
)

for c in commands:
    subprocess.run(shlex.split(c))
    time.sleep(0.5)

