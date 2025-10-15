#!/usr/bin/env bash
set -euo pipefail
ES_URL=${ES_URL:-http://localhost:9200}
INDEX=${INDEX:-llm-telemetry}

curl -s -X PUT "$ES_URL/$INDEX" -H 'Content-Type: application/json' -d '{
  "mappings": {
    "properties": {
      "@timestamp": {"type":"date"},
      "request_id": {"type":"keyword"},
      "tenant_id": {"type":"keyword"},
      "session_id": {"type":"keyword"},
      "user": {"type":"keyword"},
      "prompt": {"type":"text"},
      "response": {"type":"text"},
      "tactic": {"type":"keyword"},
      "technique": {"type":"keyword"},
      "detection": {"type":"keyword"},
      "severity": {"type":"keyword"},
      "action": {"type":"keyword"},
      "pii_entities": {"type":"keyword"},
      "client_ip": {"type":"ip"},
      "atlas_technique_id": {"type":"keyword"},
      "atlas_technique_name": {"type":"keyword"},
      "tool_calls": {
        "type":"nested",
        "properties": {
          "tool": {"type":"keyword"},
          "args": {"type":"text"}
        }
      }
    }
  }
}'
echo
echo "Index $INDEX created (or already exists)."