import os, json, re
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

import requests
from stix2 import parse as stix_parse

# Prefer local file, else fetch from GitHub
LOCAL_STIX_PATH = os.getenv("ATLAS_STIX_PATH", "vendor/atlas-navigator-data/dist/stix-atlas.json")
REMOTE_STIX_URL = os.getenv("ATLAS_STIX_URL", "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json")

def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (name or "").lower()).strip()

def _get(obj, key, default=None):
    """Safe accessor for both dicts and STIX domain objects."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def _ext_id(obj):
    for ref in (_get(obj, "external_references", []) or []):
        eid = _get(ref, "external_id")
        if eid:
            return eid
    return None

@lru_cache(maxsize=1)
def load_bundle():
    """Load ATLAS STIX bundle (local if present, else remote) and parse."""
    data = None
    if os.path.exists(LOCAL_STIX_PATH):
        with open(LOCAL_STIX_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        r = requests.get(REMOTE_STIX_URL, timeout=20)
        r.raise_for_status()
        data = r.json()
    # parse() returns a Bundle object; some child items may remain dicts if custom
    return stix_parse(data, allow_custom=True)

@lru_cache(maxsize=1)
def build_indexes():
    b = load_bundle()
    # b is a Bundle; get its 'objects' robustly
    objs = getattr(b, "objects", None)
    if objs is None and isinstance(b, dict):
        objs = b.get("objects", [])
    objs = objs or []

    techniques = [o for o in objs if _get(o, "type") == "attack-pattern"]
    mitigations = [o for o in objs if _get(o, "type") == "course-of-action"]
    rels = [o for o in objs if _get(o, "type") == "relationship" and _get(o, "relationship_type") == "mitigates"]

    tech_by_id = {}
    tech_by_ext = {}
    tech_by_name = {}

    for t in techniques:
        tid = _get(t, "id")
        name = _get(t, "name") or ""
        ext = _ext_id(t)
        if tid:
            tech_by_id[tid] = t
        if ext:
            tech_by_ext[ext] = t
        if name:
            tech_by_name[_normalize(name)] = t

    mit_by_id = { _get(m, "id"): m for m in mitigations if _get(m, "id") }

    # technique -> [mitigations]
    mit_by_tech: Dict[str, List] = {}
    for r in rels:
        src = _get(r, "source_ref")
        tgt = _get(r, "target_ref")
        if tgt in tech_by_id and src in mit_by_id:
            mit_by_tech.setdefault(tgt, []).append(mit_by_id[src])

    return {
        "tech_by_id": tech_by_id,
        "tech_by_ext": tech_by_ext,
        "tech_by_name": tech_by_name,
        "mit_by_tech": mit_by_tech,
    }

def list_techniques() -> List[Tuple[str, str]]:
    idx = build_indexes()
    out = []
    for ext, t in idx["tech_by_ext"].items():
        out.append((ext, _get(t, "name", "")))
    return sorted(out, key=lambda x: x[0] or "")

def lookup_by_name(name: str) -> Optional[dict]:
    if not name:
        return None
    idx = build_indexes()
    key = _normalize(name)
    t = idx["tech_by_name"].get(key)

    if not t:
        # very simple fallback “contains” matching
        for k, cand in idx["tech_by_name"].items():
            if key in k or k in key:
                t = cand
                break
    if not t:
        return None

    ext = _ext_id(t)
    mitigs = []
    for m in (idx["mit_by_tech"].get(_get(t, "id"), []) or []):
        mid = _ext_id(m)
        mitigs.append({"id": mid, "name": _get(m, "name", "")})

    return {
        "atlas_technique_id": ext,
        "atlas_technique_name": _get(t, "name", ""),
        "mitigations": mitigs,
    }
