


# Demo 3

## Command to trigger the IBI

```bash
curl -X POST http://localhost:8000/intents \
-H "Content-Type: application/json" \
-d '{
    "intent_type": "prevention",
    "threat": "ddos_download",
    "host": ["192.168.56.5", "192.168.56.3"],
    "duration": 600
}'
```