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
    ```
    docker compose -f docker-compose.prod.yml build
    docker compose -f docker-compose.prod.yml up
    ```
  - Development environment
    ```
    docker compose -f docker-compose.dev.yml build 
    docker compose -f docker-compose.dev.yml up
    ```

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