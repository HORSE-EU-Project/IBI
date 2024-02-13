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

1. Install Docker and its dependencies.

2. Clone the project and cd into the directory of the project, then run:
    ```
    sudo docker build -t ibi_horse .
    ```

3. After the build, run:
    ```
    sudo docker run --network host ibi_horse
    ```


