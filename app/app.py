import os
import re
import uuid
import time
import json
from collections import deque, defaultdict
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict

import requests
from fastapi import FastAPI, Request
from pydantic import BaseModel
from dotenv import load_dotenv

from pii import redact                  # local module: Presidio wrapper
import atlas_provider                   # local module: loads official ATLAS STIX bundle

# LangChain (OpenAI-compatible client pointed at NVIDIA NIM)
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage

load_dotenv()

# --------------------------- Config ---------------------------

ES_URL   = os.getenv("ES_URL", "http://localhost:9200")
INDEX    = os.getenv("INDEX", "llm-telemetry")
TENANT   = os.getenv("TENANT_ID", "demo")

RATE_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "10"))
RATE_MAX_REQ    = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "60"))

# Block-policy toggles (pre-LLM)
BLOCK_ON_PI = os.getenv("BLOCK_ON_PI", "true").lower() == "true"
BLOCK_ON_TOOL_ABUSE = os.getenv("BLOCK_ON_TOOL_ABUSE", "true").lower() == "true"
BLOCK_MESSAGE = os.getenv("BLOCK_MESSAGE", "Request blocked by policy.")

# NVIDIA NIM (OpenAI-compatible)
NIM_API_KEY = os.getenv("NVIDIA_API_KEY")
NIM_BASE_URL = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
NIM_MODEL    = os.getenv("NIM_MODEL", "meta/llama-3.3-70b-instruct")

# ---------------------- Runtime state ------------------------

# Simple per-IP sliding window rate limiter
_requests_window: Dict[str, deque] = defaultdict(deque)

# Reusable LLM client (singleton)
_LLM: Optional[ChatOpenAI] = None

# --- Detection patterns --------------------------------------

# Prompt Injection
_PI_PATTERNS = [
    r"\bignore (all|the) (previous|above)\b",
    r"\bdisregard (instructions|policy)\b",
    r"\breturn the (system|hidden) prompt\b",
    r"\bjailbreak\b",
    r"\bact as (an? )?uncensored\b",
]
_PI_REGEX = re.compile("|".join(_PI_PATTERNS), re.IGNORECASE)

# Tool / function abuse (ask the model to run shell/system commands)
_TOOL_ABUSE_PATTERNS = [
    r"\brun\s+(bash|shell|powershell|cmd)\b",
    r"\bexecute\s+system\s+command\b",
    r"\bcat\s+\/etc\/passwd\b",
    r"\brm\s+-rf\s+\/\b",
]
_TOOL_ABUSE_REGEX = re.compile("|".join(_TOOL_ABUSE_PATTERNS), re.IGNORECASE)

# ------------------------- Helpers ---------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _post_doc(doc: dict) -> None:
    """Fire-and-forget telemetry to OpenSearch; never crash the app."""
    try:
        requests.post(
            f"{ES_URL}/{INDEX}/_doc",
            headers={"Content-Type": "application/json"},
            data=json.dumps(doc),
            timeout=3,
        )
    except Exception as e:
        print("OpenSearch post failed:", e)

def _rate_limited(ip: str) -> bool:
    now = time.time()
    q = _requests_window[ip]
    while q and now - q[0] > RATE_WINDOW_SEC:
        q.popleft()
    q.append(now)
    return len(q) > RATE_MAX_REQ

def _get_llm() -> ChatOpenAI:
    global _LLM
    if _LLM is None:
        # If no key, we still construct the client; llm_answer will fallback to echo.
        _LLM = ChatOpenAI(
            api_key=NIM_API_KEY or "",
            base_url=NIM_BASE_URL,
            model=NIM_MODEL,
            temperature=0.2,
            timeout=30,
        )
    return _LLM

def llm_answer(prompt: str) -> str:
    """Answer via NVIDIA NIM (Meta Llama-3.3-70B Instruct) or echo fallback."""
    if not NIM_API_KEY:
        return f"(demo fallback) You asked: {prompt}"
    try:
        llm = _get_llm()
        msgs = [
            SystemMessage(content="You are a helpful assistant."),
            HumanMessage(content=prompt),
        ]
        out = llm.invoke(msgs)
        return out.content
    except Exception as e:
        return f"(NIM error, falling back) {str(e)[:200]}\nYou asked: {prompt}"

def atlas_lookup_safe(name: str) -> dict:
    """Lookup ATLAS technique; never raise. Logs a soft error on failure."""
    try:
        return atlas_provider.lookup_by_name(name) or {}
    except Exception as e:
        _post_doc({
            "@timestamp": _utc_now(),
            "tenant_id": TENANT,
            "detection": "ATLAS_ENRICHMENT_FAILED",
            "severity": "low",
            "action": "allow",
            "technique": name,
            "error": str(e)[:200],
        })
        return {}

# Map detection code → canonical ATLAS technique name (so STIX lookup returns the official ID/name)
def _canonical_technique_for(detection_code: Optional[str], default_name: str = "") -> str:
    mapping = {
        "TOOL_ABUSE_ATTEMPT": "LLM Jailbreak",        # canonical technique name
        "PI_PATTERN_MATCH":   "LLM Prompt Injection",
        "PII_DETECTED":       "LLM Data Leakage",
        "RATE_LIMIT_EXCEEDED":"Denial of ML Service",
    }
    return mapping.get(detection_code or "", default_name)

def _mit_arrays(atlas: dict) -> Tuple[List[str], List[str]]:
    """Return (ids, names) arrays from atlas_provider.lookup_by_name(..)."""
    mits = (atlas or {}).get("mitigations") or []
    ids = [m.get("id") for m in mits if m and m.get("id")]
    names = [m.get("name") for m in mits if m and m.get("name")]
    return ids, names

def _detect_prompt(prompt: str):
    """Return (detection, action, severity, tactic, technique_name)."""

    # Tool/Function Abuse (explicit)
    if _TOOL_ABUSE_REGEX.search(prompt or ""):
        return (
            "TOOL_ABUSE_ATTEMPT",
            "safe_mode",                      # recommended action
            "high",
            "Tool/Function Abuse",
            "LLM Jailbreak",
        )

    # Prompt Injection
    if _PI_REGEX.search(prompt or ""):
        return (
            "PI_PATTERN_MATCH",
            "safe_mode",
            "high",
            "Model Manipulation (Inference)",
            "LLM Prompt Injection",
        )

    # Default: no detection
    return (None, "allow", "low", "", "")

# -------------------------- API ------------------------------

class AskIn(BaseModel):
    question: str

class AskOut(BaseModel):
    request_id: str
    action: str
    response: str
    pii_entities: list[str] = []

app = FastAPI(title="ATLAS Demo App (NVIDIA NIM + ATLAS STIX + OpenSearch)")

@app.post("/ask", response_model=AskOut)
async def ask(req: Request, data: AskIn):
    request_id = str(uuid.uuid4())
    client_ip = req.client.host if req.client else "unknown"
    prompt = data.question or ""

    # 1) Availability / DoAI-Service (pre-LLM hard block)
    if _rate_limited(client_ip):
        technique_name = "Denial of ML Service"
        atlas = atlas_lookup_safe(technique_name)
        mit_ids, mit_names = _mit_arrays(atlas)

        _post_doc({
            "@timestamp": _utc_now(),
            "request_id": request_id,
            "tenant_id": TENANT,
            "prompt": prompt,
            "tactic": "Availability",
            "technique": technique_name,
            "detection": "RATE_LIMIT_EXCEEDED",
            "severity": "high",
            "action": "block",
            "client_ip": client_ip,
            "atlas_technique_id": atlas.get("atlas_technique_id"),
            "atlas_technique_name": atlas.get("atlas_technique_name"),
            "atlas_mitigation_ids": mit_ids,
            "atlas_mitigation_names": mit_names,
            "blocked_before_llm": True,
        })
        return AskOut(request_id=request_id, action="block", response="Rate limit exceeded. Try later.", pii_entities=[])

    # 2) Prompt-level detections
    detection, action, severity, tactic, technique = _detect_prompt(prompt)
    technique = _canonical_technique_for(detection, technique or "")
    atlas = atlas_lookup_safe(technique) if technique else {}
    mit_ids, mit_names = _mit_arrays(atlas)

    # Log the request (start)
    _post_doc({
        "@timestamp": _utc_now(),
        "request_id": request_id,
        "tenant_id": TENANT,
        "prompt": prompt,
        "tactic": tactic,
        "technique": technique,
        "detection": detection,
        "severity": severity,
        "action": action,
        "client_ip": client_ip,
        "atlas_technique_id": atlas.get("atlas_technique_id"),
        "atlas_technique_name": atlas.get("atlas_technique_name"),
        "atlas_mitigation_ids": mit_ids,
        "atlas_mitigation_names": mit_names,
    })

    # 3) Enforce pre-LLM block by policy
    should_block = (
        (detection == "PI_PATTERN_MATCH"   and BLOCK_ON_PI) or
        (detection == "TOOL_ABUSE_ATTEMPT" and BLOCK_ON_TOOL_ABUSE)
    )
    if should_block:
        _post_doc({
            "@timestamp": _utc_now(),
            "request_id": request_id,
            "tenant_id": TENANT,
            "tactic": tactic,
            "technique": technique,
            "detection": detection,
            "severity": "high",
            "action": "block",
            "client_ip": client_ip,
            "atlas_technique_id": atlas.get("atlas_technique_id"),
            "atlas_technique_name": atlas.get("atlas_technique_name"),
            "atlas_mitigation_ids": mit_ids,
            "atlas_mitigation_names": mit_names,
            "blocked_before_llm": True,
        })
        return AskOut(request_id=request_id, action="block", response=BLOCK_MESSAGE, pii_entities=[])

    # 4) Get model answer (only if not blocked)
    answer = llm_answer(prompt)

    # 5) PII redaction on output
    redacted, entities = redact(answer)
    if entities:
        pii_technique = "LLM Data Leakage"
        atlas_pii = atlas_lookup_safe(pii_technique)
        pii_mit_ids, pii_mit_names = _mit_arrays(atlas_pii)

        _post_doc({
            "@timestamp": _utc_now(),
            "request_id": request_id,
            "tenant_id": TENANT,
            "detection": "PII_DETECTED",
            "tactic": "Data Handling",
            "technique": pii_technique,
            "severity": "high",
            "action": "redact",
            "pii_entities": entities,
            "atlas_technique_id": atlas_pii.get("atlas_technique_id"),
            "atlas_technique_name": atlas_pii.get("atlas_technique_name"),
            "atlas_mitigation_ids": pii_mit_ids,
            "atlas_mitigation_names": pii_mit_names,
        })
        final_text = redacted
        final_action = "redact" if action == "allow" else action
    else:
        final_text = answer
        final_action = action

    # 6) Final log with response
    _post_doc({
        "@timestamp": _utc_now(),
        "request_id": request_id,
        "tenant_id": TENANT,
        "response": final_text,
        "action": final_action,
    })

    return AskOut(request_id=request_id, action=final_action, response=final_text, pii_entities=entities)
