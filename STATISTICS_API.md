# IBI Statistics API

This document describes the statistics endpoints for the IBI (Intent-Based Intelligence) module.

## Overview

The statistics API provides comprehensive information about the IBI system's intents, threats, and mitigation actions. It is designed to support dashboard applications that need real-time system overview and detailed statistics.

## Endpoints

### 1. General Overview

**GET** `/statistics/overview`

Returns a summary of all system statistics including counts of intents, threats, and mitigations.

**Response:**
```json
{
  "intents": {
    "total": 10,
    "active": 8,
    "expired": 2,
    "satisfied": 5
  },
  "threats": {
    "total": 15,
    "by_status": {
      "NEW": 3,
      "UNDER_EMULATION": 2,
      "UNDER_MITIGATION": 4,
      "REINCIDENT": 1,
      "MITIGATED": 5
    }
  },
  "mitigations": {
    "total": 20,
    "enabled": 18,
    "disabled": 2,
    "by_category": {
      "mitigation": 10,
      "prevention": 6,
      "detection": 4
    }
  }
}
```

### 2. Intents Statistics

**GET** `/statistics/intents`

Returns detailed information about all intents with their status and grouping options.

**Response:**
```json
{
  "total_intents": 10,
  "intents": [
    {
      "uid": "uuid",
      "intent_type": "dns_ddos",
      "threat": "dns_ddos",
      "host": ["192.168.1.1"],
      "duration": 3600,
      "start_time": 1640995200,
      "end_time": 1640998800,
      "satisfied": false,
      "timedout": false,
      "status": "active"
    }
  ],
  "grouped_by_type": {
    "dns_ddos": [...],
    "ntp_ddos": [...]
  },
  "grouped_by_threat": {
    "dns_ddos": [...],
    "ntp_ddos": [...]
  }
}
```

### 3. Threats Statistics

**GET** `/statistics/threats`

Returns detailed information about all detected threats with their status and grouping options.

**Response:**
```json
{
  "total_threats": 15,
  "threats": [
    {
      "uid": "uuid",
      "threat_type": "dns_ddos",
      "threat_name": "dns_ddos",
      "hosts": ["192.168.1.1"],
      "start_time": 1640995200,
      "end_time": 1640998800,
      "last_update": 1640995200,
      "status": "NEW",
      "expired": false
    }
  ],
  "grouped_by_type": {
    "dns_ddos": [...],
    "ntp_ddos": [...]
  },
  "grouped_by_name": {
    "dns_ddos": [...],
    "ntp_ddos": [...]
  },
  "grouped_by_status": {
    "NEW": [...],
    "UNDER_EMULATION": [...],
    "UNDER_MITIGATION": [...],
    "REINCIDENT": [...],
    "MITIGATED": [...]
  }
}
```

### 4. Mitigations Statistics

**GET** `/statistics/mitigations`

Returns detailed information about all mitigation actions with their categories and status.

**Response:**
```json
{
  "total_mitigations": 20,
  "mitigations": [
    {
      "uid": "uuid",
      "name": "Block DNS Traffic",
      "category": "mitigation",
      "threats": ["dns_ddos"],
      "fields": ["source_ip", "destination_port"],
      "priority": 0,
      "enabled": true,
      "parameters": {}
    }
  ],
  "grouped_by_category": {
    "mitigation": [...],
    "prevention": [...],
    "detection": [...]
  },
  "enabled": [...],
  "disabled": [...],
  "grouped_by_priority": {
    "0": [...],
    "1": [...]
  }
}
```

### 5. Associations Statistics

**GET** `/statistics/associations`

Returns information about associations between threats and mitigation actions.

**Response:**
```json
{
  "total_associations": 8,
  "associations": [
    {
      "threat_uid": "uuid",
      "threat_type": "dns_ddos",
      "threat_name": "dns_ddos",
      "threat_status": "UNDER_MITIGATION",
      "mitigations": [
        {
          "uid": "uuid",
          "name": "Block DNS Traffic",
          "category": "mitigation"
        }
      ],
      "mitigation_count": 1
    }
  ],
  "grouped_by_threat_type": {
    "dns_ddos": [...],
    "ntp_ddos": [...]
  },
  "mitigation_usage_by_category": {
    "mitigation": 5,
    "prevention": 2,
    "detection": 1
  }
}
```

## Dashboard Integration

The statistics API is designed to work with the IBI dashboard. The dashboard includes:

1. **Overview Cards**: Display key metrics like total intents, threats, and mitigations
2. **Threat Status Overview**: Visual representation of threats by status
3. **Detailed Tables**: Recent intents, threats, and mitigation actions
4. **Real-time Updates**: Automatic refresh every 30 seconds

### Accessing the Dashboard

- **Main Dashboard**: `GET /`
- **Statistics Dashboard**: `GET /statistics`

## Error Handling

All endpoints return appropriate HTTP status codes:

- `200 OK`: Successful response
- `500 Internal Server Error`: Server error with error details in response body

Error responses include:
```json
{
  "error": "Error description"
}
```

## Usage Examples

### Using curl

```bash
# Get overview statistics
curl http://localhost:8000/statistics/overview

# Get intents statistics
curl http://localhost:8000/statistics/intents

# Get threats statistics
curl http://localhost:8000/statistics/threats
```

### Using JavaScript

```javascript
// Fetch overview statistics
const response = await fetch('/statistics/overview');
const overview = await response.json();
console.log(`Total intents: ${overview.intents.total}`);
console.log(`Total threats: ${overview.threats.total}`);
```

## Data Sources

The statistics are generated from the following data sources:

- **Intents**: Core intents stored in the InMemoryStore
- **Threats**: Detected threats with their current status
- **Mitigations**: Available mitigation actions and their configuration
- **Associations**: Relationships between threats and applied mitigations

All data is retrieved from the singleton InMemoryStore instance, ensuring consistency across all endpoints.
