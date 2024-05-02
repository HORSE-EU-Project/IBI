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

2. Install Elasticsearch.

3. Clone the project and cd into the directory of the project, then run:
    ```
    sudo docker build -t ibi_horse .
    ```

4. After the build, run:
    ```
    sudo docker run --network host ibi_horse
    ```

# Run Development Environment with Docker
1. Pull the Python Image from Docker Hub
    ```
    docker pull python:3.8.10
    docker pull docker.elastic.co/elasticsearch/elasticsearch:8.13.2
    ```

2. Create a dedicated Docker Network for ElasticSearch
    ```
    docker network create elastic
    ```

3. Run ElastiSearch container (no need to run it locally)
    ```
    docker run --name es01 --rm -it --net elastic -p 9200:9200 -p 9300:9300 -m 1GB -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:8.13.2
    ```
   
4. Run HORSE IBI Software
    4.1. One-line command
    ```
     sudo docker run --name horse-ibi --rm -it --net elastic -p 7777:7777 --mount src=`pwd`,target=/code,type=bind -w /code python:3.8.10 sh -c "pip install -r requirements.txt && python app/main.py"
    ```

    4.2. For debugging and info
    ```
    sudo docker run --name horse-ibi --rm -it --net elastic -p 7777:7777 --mount src=`pwd`,target=/code,type=bind -w /code python:3.8.10 sh
    ```
    From inside the container
    ```
    pip install -r requirements.txt
    python app/main.py
    ```

