# Installing and managing requirements with venv

1. Create a new virtual environment (.venv) (Only required for the first time)
   ```
   $ python3 -m venv .venv
   ```
    1.1. Install the required python packages
    ```
    pip install -r requirements.txt
    ```

2. Activate the virtual environment
    ```
    $ source .venv/bin/activate
    ```


# Steps to run the IBI

1. Clone the project and cd into the directory of the project, then install the requirements.
    ```
    pip install -r requirements.txt
    ```

2. Run the start.py file, with the IP of your machine.
    ```
    python3 start.py "IP.AD.DRE.SS"
    ```

Example, assuming that the IP of your machine is 192.168.56.1:
    ```
    python3 start.py 192.168.56.1
    ```
    
It creates six terminals, the first four host the APIs that the IBI would be communicating with.

You would be faced with the sixth terminal which is where the intent manager runs and gives out information.

The fifth terminal is where you can delete an intent any time by running the commmand below, while "IP.AD.DRE.SS" is the IP of your machine:
    ```
    python3 delete_intents.py "IP.AD.DRE.SS"
    ```

3. To send an intent from another module running on another machine to the IBI on your machine, copy the file 'put_intents.py' and paste in the other machine and then run the command below, while "IP.AD.DRE.SS" is the IP of your machine:
    ```
    python3 put_intents.py "IP.AD.DRE.SS"
    ```

An example of an intent is already inside the put_intents.py file, you can modify the parameters how you want.

4. When the what-if question has been sent for a prevention intent, to send a reply to the what-if question from another module running on another machine to the IBI on your machine, copy the file 'put_whatif.py' and paste in the other machine and then run the command below, while "IP.AD.DRE.SS" is the IP of your machine:
    ```
    python3 put_whatif.py "IP.AD.DRE.SS"
    ```

An example of a what-if reply is already inside the put_whatif.py file, you can modify the parameters how you want.
