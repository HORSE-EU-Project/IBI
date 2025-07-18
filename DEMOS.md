# Instructions to Run the Demos

## Demo 3

### Command to trigger the IBI

```bash
curl -X POST http://localhost:8080/intents \
-H "Content-Type: application/json" \
-d '{
    "intent_type": "prevention",
    "threat": "ddos_download",
    "host": ["192.168.56.5", "192.168.56.3"],
    "duration": 600
}'
```


### Simulate NDT answer to IBI

```bash
curl -X POST http://127.0.0.1:8080/impact-analysis \
    -H "Content-Type: application/json" \
    -d '{
        "id": "ec61211b-6074-4e6d-818a-6b6e33e2ca7e,",
        "topology_name": "horse_ddos",
        "attack": "DDoS_reverse",
        "what": {
                "KPIs": {
                    "element": {
                        "node": "ceos-1",
                        "interface": "eth6"
                    },
                    "metric": "packets-per-second",
                    "result": {
                        "value": "1.2",
                        "unit": "packets-per-second"
                    }
                }
        }
}'
```