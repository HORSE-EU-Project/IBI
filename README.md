# Intent-Based Interface

The IBI is a software prototype developed within the scope of 
[HORSE project](ibi-api). The main goal of the module is to match intents that 
represent the desired state of the system or network and apply policies to 
achieve those states or, in other words, to fulfill the intents. Currently, the 
IBI can receive intents encoded as JSON files through a RESTful API or a 
graphical user interface (GUI). The receives security intents that could be 
mitigation or prevention intents regarding threats affecting the network. Within 
the IBI, the intents are processed and matched with the policies that are sent 
to the [RTR module](https://github.com/HORSE-EU-Project/RTR).

## Development
- Download the application code:
```
git clone https://github.com/HORSE-EU-Project/IBI.git
```

- Enter the project directory
```
cd IBI
```

- Run Elastic Search on a local docker instance
```
docker run --rm --name es01-dev -p 127.0.0.1:9200:9200 -p 127.0.0.1:9300:9300 -e "discovery.type=single-node" -e "xpack.security.enabled=false" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" elasticsearch:8.18.1
```

- Run the application
```
uv run app/main.py
```


## Installation

- Download the application code:
    ```
    git clone https://github.com/HORSE-EU-Project/IBI.git
    ```
- Change the current directory to IBI.
    ```
    cd IBI

- Build and run the software as Docker container:
  - Production environment
    - Build the Docker Image
    ```
    docker compose -f docker-compose.prod.yml build
    ```
    - Create configuration file
      ```
      mkdir config
      cp ./app/config.yml ./config/prod.yml
      ```
    - Run the Production Environment docker image:
      ```
      docker compose -f docker-compose.prod.yml up
      ```
> The production environment takes the current snapshot of the files in the
> current directory, creates a container image with the files and runs the 
> created image (further changes in the local files will only be applied to the
> container image when the image is rebuilt.)

  - Development environment
    ```
    docker compose -f docker-compose.dev.yml build 
    docker compose -f docker-compose.dev.yml up
    ```

> The development environment does not copy files to a Docker image. Instead, 
> it maps (binds) the filesystem from the local folder to the docker app. It is 
> useful for development, because changes in the local file system are 
> automatically applied to the containerized application (in other words, you do 
> not need to rebuild the docker image to see the changes).

- Stop the execution of the software:
  - Production environment
    ```
    docker compose -f docker-compose.prod.yml down
    ```
  - Development environment
    ```
    docker compose -f docker-compose.dev.yml down
    ```

# Accessing the service
- The API is available at your local IP address (or localhost), on port 7777.
- The ElasticSearch Instance is exposted at port 9200 and 9300, also at your local IP (or localhost).

# API Call examples

## Security intents
```
  # Example 1 
  {
    "intent_type": "mitigation",
    "threat": "ddos_dns",
    "host": ['dns-c5'],
    "duration": 9650
  }

  # Example 2
  {
    "intent_type": "mitigation",
    "threat": "ddos_dns",
    "host": ['dns-c1', 'dns-c2',
    'gnb', 'upf',
    'dns-c4'],
    "duration": 3000
  }

  # Example 3
  {
    "intent_type": "prevention",
    "threat": "ddos_dns",
    "host": ['dns-c6', 'dns-c8'],
    "duration": 400
  }
```

## Operator's QoS requirements

```
  {
    'intent_type': 'qos_ntp',
    'name': 'reliability',
    'value': 0.9,
    'unit': '1',
    'host': ['dns-s', 'dns-c1']
  }

  {
    'intent_type': 'qos_ntp',
    'name': 'reliability',
    'value': 90,
    'unit': '%',
    'host': ['dns-s', 'dns-c1']
  }

  {
    'intent_type': 'qos_dns',
    'name': 'latency',
    'value': 0.2,
    'unit': 'ms',
    'host': ['dns-s', 'dns-c1']
  }

  {
    'intent_type': 'qos_dns',
    'name': 'latency',
    'value': 0.15,
    'unit': 'μs',
    'host': ['dns-s', 'dns-c1']
  }

  {
    'intent_type': 'qos_dns',
    'name': 'latency',
    'value': 1.0,
    'unit': 's',
    'host': ['dns-s', 'dns-c1']
  }

  {
    'intent_type': 'qos_pfcp',
    'name': 'bandwidth',
    'value': 5000,
    'unit': 'mbps',
    'host': ['dns-s', 'dns-c1']
  }

  {
    'intent_type': 'qos_pfcp',
    'name': 'bandwidth',
    'value': 24,
    'unit': 'gbps',
    'host': ['dns-s', 'dns-c1']
  }
  
  {
    'intent_type': 'qos_pfcp',
    'name': 'bandwidth',
    'value': 60000,
    'unit': 'kbps',
    'host': ['dns-s', 'dns-c1']
  }
  
  {
    'intent_type': 'qos_pfcp',
    'name': 'bandwidth',
    'value': 859000,
    'unit': 'bps',
    'host': ['dns-s', 'dns-c1']
  }
```

## DT what-if responses (only for prevention intents)
```
  # Host dns-c6
  {
    "id": "ZX9TOSZNV",
    "host": 'dns-c6',
    "kpi_measured": "bandwidth",
    "kpi_value": "1000",
    "kpi_unit": "mbps"
  }
  
  # Host dns-c8
  {
    "id": "HTGFS9W9W",
    "host": 'dns-c8',
    "kpi_measured": "latency",
    "kpi_value": "0.5",
    "kpi_unit": "ms"
  }
```