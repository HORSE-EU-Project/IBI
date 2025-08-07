# Horse IBI - Intent-Based Infrastructure AI Coding Instructions

## System Overview
This is an Intent-Based Infrastructure (IBI) system implementing MAPE-K architecture for network security. The system receives security intents from a DTE (Digital Twin Engine) module and orchestrates network protection through automated policy enforcement.

## Core Architecture & Data Flow

### MAPE-K Components
- **Monitor**: DTE sends intents via REST API (`/intents` endpoint)
- **Analyze**: `IntentPipeline` processes intents and queries external systems
- **Plan**: `Recommender` generates mitigation/prevention actions from stored policies
- **Execute**: Actions validated by CAS and executed via RTR
- **Knowledge**: In-memory storage (`InMemoryStore`) with Elasticsearch persistence

### Intent Processing Flow
1. **Intent Reception**: `/intents` POST → `DTEController.process_dte_intent()`
2. **State Management**: Creates `CoreIntent` + `DetectedThreat` objects in `InMemoryStore`
3. **Pipeline Processing**: `IntentPipeline.process_intents()` runs in background thread
4. **External Integrations**: CKB → Recommender → CAS → RTR (for mitigation) or IADT → CAS → RTR (for prevention)

### Key Domain Models
- `DTEIntent` (API input) → `CoreIntent` (internal processing) → `DetectedThreat` (system state)
- Intent types: `MITIGATION` (immediate action) vs `PREVENTION` (what-if analysis first)
- Threat status lifecycle: `DETECTED` → `UNDER_MITIGATION` → `MITIGATED`

## Development Patterns

### Project Structure
```
app/
├── models/           # Data models (api_models.py, core_models.py)
├── controllers/      # Business logic (dte_controller.py)
├── routers/         # FastAPI endpoints (intents.py, iandt.py)
├── data/            # In-memory storage (store.py), static data (mitigations.py)
├── integrations/    # External service clients (external.py)
├── pipeline.py      # Background intent processing
└── main.py         # FastAPI application + background tasks
```

### Configuration Management
- Development: `config.yml` (local Elasticsearch, disabled external services)
- Production: `config-prod.yml` (Docker service names, enabled integrations)
- Access via `config.py` module: `config.ES_URL`, `config.RTR_URL`, etc.

### External Service Integration Pattern
All external services use singleton pattern with graceful degradation:
```python
class ExternalService:
    def __init__(self):
        if self.service_url:
            self.enabled = True
        else:
            self.enabled = False
            self._logger.info("Service disabled, logging only")
```

### Data Storage
- **Primary**: `InMemoryStore` singleton with thread-safe operations
- **Persistence**: Elasticsearch via `ElasticSearchClient` (also singleton)
- **Static Data**: Mitigation mappings in `data/mitigations.py`

## Development Commands

### Local Development
```bash
# Start Elasticsearch
docker run --rm --name es01-dev -p 127.0.0.1:9200:9200 -e "discovery.type=single-node" -e "xpack.security.enabled=false" elastic/elasticsearch:8.11.0

# Install dependencies
uv sync

# Run application
uv run app/main.py
```

### Docker Development
```bash
# Build and run full stack
docker-compose -f docker-compose.dev.yml up --build

# Production deployment
docker-compose -f docker-compose.prod.yml up -d
```

### API Testing
Use `tests/dte.rest` for HTTP requests. Key endpoints:
- `POST /intents` - Submit security intents
- `POST /impact-analysis` - Receive IADT responses (prevention intents only)

## Critical Integration Points

### External Services (all HTTP-based)
- **CKB**: Threat intelligence queries (`/mitigations`)
- **CAS**: Compliance validation before execution
- **RTR**: Network policy enforcement (`/workflows`)
- **IADT**: Impact analysis for prevention intents (async responses via `/impact-analysis`)

### Background Processing
`IntentPipeline.process_intents()` runs every 5 seconds via threading:
- Processes new intents from `InMemoryStore`
- Handles different flows for mitigation vs prevention intents
- Updates intent status throughout lifecycle

### Elasticsearch Compatibility
- Uses headers for v8 compatibility: `"Accept": "application/vnd.elasticsearch+json; compatible-with=8"`
- Indices: `intents`, `mitigations`, `system_states`
- Connection singleton with retry logic

## Project-Specific Conventions

### Logging
```python
from utils.log_config import setup_logging
logger = setup_logging(__file__)
```

### Error Handling
External integrations use pattern:
```python
except requests.exceptions.MissingSchema:
    logger.info("Service disabled, logging only")
except requests.exceptions.ConnectionError:
    logger.error("Connection failed")
    raise
```

### Thread Safety
Singletons use double-checked locking:
```python
_instance = None
_lock = Lock()

def __new__(cls):
    if cls._instance is None:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
```

### Configuration
- Development: Services often disabled/mocked for local testing
- All URLs configurable via YAML files
- Environment-specific docker-compose files

## Testing & Debugging
- Use `tests/dte.rest` for API testing
- Check logs for external service integration status
- Pipeline processing logs every 5 seconds
- Elasticsearch health via `GET /_cluster/health`
