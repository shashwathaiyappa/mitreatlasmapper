#!/usr/bin/env python3
import os, json, requests

ES_URL = os.getenv("ES_URL","http://localhost:9200")
INDEX = os.getenv("INDEX","llm-telemetry")

resp = requests.get(f"{ES_URL}/{INDEX}/_search",
    headers={"Content-Type":"application/json"},
    data=json.dumps({
      "size": 0,
      "aggs": {
        "techniques": {
          "terms": {"field": "atlas_technique_id", "size": 200},
          "aggs": {"names": {"terms": {"field":"atlas_technique_name","size":1}}}
        }
      }
    }),
    timeout=10
)
resp.raise_for_status()
buckets = resp.json().get("aggregations",{}).get("techniques",{}).get("buckets",[])

layer = {
  "name": "ATLAS coverage from demo logs",
  "version": "4.3",
  "description": "Techniques observed in demo (auto-generated).",
  "domain": "atlas",
  "techniques": []
}
for b in buckets:
  tid = b["key"]
  if not tid: continue
  name = b.get("names",{}).get("buckets",[{"key":""}])[0]["key"]
  layer["techniques"].append({
    "techniqueID": tid,
    "comment": name,
    "enabled": True,
    "metadata": [{"name":"source","value":"llm-telemetry"}]
  })

print(json.dumps(layer, indent=2))
