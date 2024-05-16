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


# Steps to run the IBI (needs update to use ES as docker)

> [!WARNING]
> Deprecated. It uses a local installation of ElasticSearch.
> Please use the instructions below.

1. Install Docker and its dependencies.

2. Install Elasticsearch.

3. Clone the project and cd into the directory of the project, then run:
    ```
    sudo docker build -t ibi_horse .
    ```

4. After the build, run:
    ```
    sudo docker run --network host ibi_horse
    ```

# Run HORSE IBI for development

## Create a dedicated Docker Network for ElasticSearch
    ```
    docker network create elastic
    ```

## Pull ElastichSearch image and run it
    ```
    docker pull docker.elastic.co/elasticsearch/elasticsearch:8.13.2
    docker run --name es01 --rm -it --net elastic -p 9200:9200 -p 9300:9300 -m 1GB -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:8.13.2
    ```

    > [!NOTE]
    > Keep the ElastichSearch running and do not clode the terminal


## Run the HORSE IBI App

### **Open a new terminal** and navigate to the Project folder
    In a new terminal window (assuming the project is at `~/devel/horse-ibi/`)
    ```
    cd ~/devel/horse-ibi/
    ```

### Pull the Python Image from Docker Hub
    ```
    docker pull python:3.8.10

    ```
### Run HORSE IBI Software
    
    #### Option 1: One-line command
    ```
     sudo docker run --name horse-ibi --rm -it --net elastic -p 7777:7777 --mount src=`pwd`,target=/code,type=bind -w /code python:3.8.10 sh -c "pip install -r requirements.txt && python app/main.py"
    ```

    > [!NOTE]
    > Edit the files in your local directory (e.g., `~/devel/horse-ibi/`) and it will be updates in the running docker container

    #### Option 2: Multiple commands for debugging and info
    
    1. Run the Docker container
    ```
    sudo docker run --name horse-ibi --rm -it --net elastic -p 7777:7777 --mount src=`pwd`,target=/code,type=bind -w /code python:3.8.10 sh
    ```
    
    2. Runt the app from the container command line:
    ```
    pip install -r requirements.txt
    python app/main.py
    ```

    > [!NOTE]
    > Edit the files in your local directory (e.g., `~/devel/horse-ibi/`) and it will be updates in the running docker container


# Using the service

- The API is available at your local IP address (or localhost), on port 7777.
- The Elastic Search Instance is exposted at port 9200, also at your local IP (or localhost).