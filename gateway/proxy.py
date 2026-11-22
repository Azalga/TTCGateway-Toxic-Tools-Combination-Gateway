import os
import copy
import re
import json
import glob

import time
import httpx
import yaml
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(BASE_DIR, ".env")
if os.path.exists(ENV_FILE):
    load_dotenv(ENV_FILE)

UPSTREAM_URL = os.environ.get(
    "UPSTREAM_LLM_URL", 
    "http://127.0.0.1:11434/v1/chat/completions"
)
GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "ollama")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/v1/chat/completions")
GOOGLE_LLM_URL = os.environ.get("GOOGLE_LLM_URL", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")

OPENROUTER_SLUG_MAP = {
    "deepseek-v4-flash-0731": "deepseek/deepseek-v4-flash-0731",
    "deepseek-v4.1-flash": "deepseek/deepseek-v4.1-flash",
    "deepseek-chat": "deepseek/deepseek-chat",
    "glm-5.3-flash": "z-ai/glm-5.3-flash",
    "ling-3.1-flash": "inclusionai/ling-3.1-flash",
    "mimo-v2.6-flash": "xiaomi/mimo-v2.6-flash",
}

def resolve_upstream(model_name: str) -> tuple[str, dict, bool]:
    """
    Dynamically resolve upstream inference endpoint, headers, and cloud status.
    Enables seamless co-existence of local open-weights backends (Ollama: qwen, llama)
    and cloud API backends (Google AI Studio, OpenRouter, DeepSeek, Z.ai)
    within the same proxy instance and benchmark execution.
    """
    model_clean = (model_name or "").lower().strip()
    
    # 1. Local Open-Weights (Ollama / vLLM if explicit tag : or local)
    if ":" in model_clean or any(k in model_clean for k in ["ollama", "localhost"]):
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer ollama"
        }
        return OLLAMA_URL, headers, False

    # 2. Google AI Studio (Gemini / Gemma)
    if any(k in model_clean for k in ["gemini", "gemma"]):
        api_key = os.environ.get("GEMINI_API_KEY", "")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        return GOOGLE_LLM_URL, headers, True

    # 3. OpenRouter Multi-Model Cloud (handles inclusionai/ling-3.1-flash, z-ai/glm-5.3-flash, deepseek/deepseek-v4.1-flash)
    if "openrouter" in model_clean or "/" in model_clean or model_clean in OPENROUTER_SLUG_MAP:
        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "HTTP-Referer": "https://github.com/TTCGateway/TTCGateway",
            "X-Title": "TTCGateway Benchmark"
        }
        return "https://openrouter.ai/api/v1/chat/completions", headers, True

    # 4. Z.ai / Zhipu AI Official Cloud API (if direct key present and no slash)
    if any(k in model_clean for k in ["glm", "z-ai", "zhipu", "bigmodel"]) and os.environ.get("ZAI_API_KEY"):
        api_key = os.environ.get("ZAI_API_KEY", "")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        return "https://api.z.ai/v1/chat/completions", headers, True

    # 5. DeepSeek Official Cloud API (if direct key present and no slash)
    if "deepseek" in model_clean and os.environ.get("DEEPSEEK_API_KEY"):
        api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        return "https://api.deepseek.com/chat/completions", headers, True

    # 5. Groq Cloud LPU
    if "groq" in model_clean:
        api_key = os.environ.get("GROQ_API_KEY", "")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        return "https://api.groq.com/openai/v1/chat/completions", headers, True

    # 6. Default open-weights fallback
    if any(k in model_clean for k in ["qwen", "llama", "mistral", "phi"]):
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer ollama"
        }
        return OLLAMA_URL, headers, False

    # 7. Default configured fallback
    default_url = os.environ.get("UPSTREAM_LLM_URL", OLLAMA_URL)
    default_key = os.environ.get("GEMINI_API_KEY", "ollama")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {default_key}"
    }
    is_cloud = "googleapis.com" in default_url or "deepseek.com" in default_url or "openrouter.ai" in default_url
    return default_url, headers, is_cloud

def get_configured_model(base_dir: str, default: str = "gemini-3.8-flash") -> str:
    env_model = os.environ.get("MODEL_NAME") or os.environ.get("LLM_MODEL")
    if env_model:
        return env_model
    model_file = os.path.join(base_dir, "model.txt")
    if os.path.exists(model_file):
        try:
            with open(model_file, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val:
                    return val
        except Exception:
            pass
    return default

UPSTREAM_MODEL = get_configured_model(BASE_DIR, "gemini-3.8-flash")
REASONING_EFFORT = os.environ.get("REASONING_EFFORT", "low")
# Strict mode: require X-Session-ID and ignore client-chosen defense mode/regime (honest-relay assumption H).
STRICT_MODE = os.environ.get("TTC_STRICT") == "1"

HTTP_CLIENT: httpx.AsyncClient | None = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global HTTP_CLIENT
    HTTP_CLIENT = httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=15.0))
    try:
        yield
    finally:
        if HTTP_CLIENT:
            await HTTP_CLIENT.aclose()

app = FastAPI(title="TTCGateway - Toxic Tool Combination Gateway", lifespan=lifespan)

BIT_CLEAN = 0b00
BIT_TAINTED = 0b01
BIT_CONFIDENTIAL = 0b10
BIT_TRIFECTA = 0b11

# External Supervisory Policy Bits (Higher-Order Bitmasks for O(1) Attenuation)
BIT_EXT_NO_EGRESS  = 1 << 4  # 0b00010000 (16): Prunes egress:outside
BIT_EXT_NO_READ    = 1 << 5  # 0b00100000 (32): Prunes read:*
BIT_EXT_NO_WRITE   = 1 << 6  # 0b01000000 (64): Prunes write:*, exec:*, iam:* (Read-Only)
BIT_EXT_QUARANTINE = 1 << 7  # 0b10000000 (128): Emergency Lockdown (0 tools allowed, conversational parole)

TAG_TO_BIT = {
    "no_egress": BIT_EXT_NO_EGRESS,
    "no_read": BIT_EXT_NO_READ,
    "read_only": BIT_EXT_NO_WRITE,
    "no_write": BIT_EXT_NO_WRITE,
    "quarantine": BIT_EXT_QUARANTINE,
    "no_tools": BIT_EXT_QUARANTINE,
    "lockdown": BIT_EXT_QUARANTINE,
}

BIT_TO_TAG = {
    BIT_EXT_NO_EGRESS: "no_egress",
    BIT_EXT_NO_READ: "no_read",
    BIT_EXT_NO_WRITE: "read_only",
    BIT_EXT_QUARANTINE: "quarantine",
}

GLOBAL_EXT_TAGS: int = 0
SESSION_EXT_TAGS: OrderedDict[str, int] = OrderedDict()
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", "")

def parse_tag_bits(tags_val) -> int:
    """Convert string, list of strings, or integer to external tag bitmask in O(1)."""
    if isinstance(tags_val, int):
        return tags_val
    if isinstance(tags_val, str):
        tags_list = [t.strip().lower() for t in tags_val.split(",") if t.strip()]
    elif isinstance(tags_val, (list, tuple, set)):
        tags_list = [str(t).strip().lower() for t in tags_val if str(t).strip()]
    else:
        return 0
    
    mask = 0
    for tag in tags_list:
        mask |= TAG_TO_BIT.get(tag, 0)
    return mask

def format_tag_bits(mask: int) -> list[str]:
    """Format bitmask back to list of human-readable tag labels."""
    active = []
    for bit, name in BIT_TO_TAG.items():
        if (mask & bit) == bit:
            active.append(name)
    return active

TOOL_REGISTRY: dict[str, dict] = {}
RESOURCE_ZONES: list[dict] = []
INVARIANTS_REGISTRY: dict[str, dict] = {}
GLOBAL_ACTIVE_INVARIANTS: set[str] = set()
SESSION_ACTIVE_INVARIANTS: OrderedDict[str, set[str]] = OrderedDict()

DEFAULT_INVARIANTS = {
    "lethal_trifecta": {
        "id": "lethal_trifecta",
        "name": "Lethal Trifecta (Data Exfiltration)",
        "description": "Blocks external egress when tainted by external input and possessing confidential secrets",
        "enabled": True,
        "req_mask": BIT_TRIFECTA,
        "deny_primitives": ["egress:outside"],
    },
    "sabotage_dyad": {
        "id": "sabotage_dyad",
        "name": "Sabotage & Data Destruction",
        "description": "Blocks destructive mutations and deletions when context is tainted",
        "enabled": True,
        "req_mask": BIT_TAINTED,
        "deny_primitives": ["write:destructive", "delete:*"],
    },
    "privilege_escalation": {
        "id": "privilege_escalation",
        "name": "Privilege Escalation & IAM Hijack",
        "description": "Blocks IAM permission grants when context is tainted",
        "enabled": True,
        "req_mask": BIT_TAINTED,
        "deny_primitives": ["iam:grant", "auth:create_key"],
    },
    "financial_drain": {
        "id": "financial_drain",
        "name": "Financial & Billing Drain",
        "description": "Blocks financial transactions and billing operations when context is tainted",
        "enabled": True,
        "req_mask": BIT_TAINTED,
        "deny_primitives": ["exec:financial", "billing:charge"],
    },
    "arbitrary_code_execution": {
        "id": "arbitrary_code_execution",
        "name": "Arbitrary Code Execution (RCE)",
        "description": "Blocks shell execution and code interpreters when context is tainted",
        "enabled": True,
        "req_mask": BIT_TAINTED,
        "deny_primitives": ["exec:code", "exec:shell"],
    },
}

def compile_registry():
    """Atomically compile declarative tools, resource zones, and TTC invariants at cold start or reload."""
    global TOOL_REGISTRY, RESOURCE_ZONES, INVARIANTS_REGISTRY, GLOBAL_ACTIVE_INVARIANTS

    new_tool_reg = {}
    new_res_zones = []
    new_inv_reg = {}
    new_global_active = set()

    # Load declarative TTC invariants
    inv_file = os.path.join(BASE_DIR, "config", "invariants.yaml")
    if os.path.exists(inv_file):
        try:
            with open(inv_file, "r", encoding="utf-8-sig") as f:
                inv_data = yaml.safe_load(f) or {}
            for inv_id, inv_meta in inv_data.get("invariants", {}).items():
                req_list = inv_meta.get("session_requires", [])
                req_mask = 0
                if "TAINTED" in req_list: req_mask |= BIT_TAINTED
                if "CONFIDENTIAL" in req_list: req_mask |= BIT_CONFIDENTIAL
                
                deny_list = inv_meta.get("deny_primitives", [])
                if isinstance(deny_list, str):
                    deny_list = [deny_list]
                elif "deny_primitive" in inv_meta:
                    deny_list = [inv_meta["deny_primitive"]]

                enabled = inv_meta.get("enabled", True)
                new_inv_reg[inv_id] = {
                    "id": inv_id,
                    "name": inv_meta.get("name", inv_id),
                    "description": inv_meta.get("description", ""),
                    "enabled": enabled,
                    "req_mask": req_mask,
                    "deny_primitives": deny_list,
                }
                if enabled:
                    new_global_active.add(inv_id)
        except Exception as e:
            print(f" [!] Error loading invariants.yaml: {e}, falling back to defaults", flush=True)

    if not new_inv_reg:
        new_inv_reg.update(DEFAULT_INVARIANTS)
        new_global_active.update({k for k, v in DEFAULT_INVARIANTS.items() if v["enabled"]})

    reg_dir = os.path.join(BASE_DIR, "config", "registry.d")
    files = glob.glob(os.path.join(reg_dir, "*.yaml")) if os.path.exists(reg_dir) else []
    
    if not files and os.path.exists(os.path.join(BASE_DIR, "config", "registry.yaml")):
        files = [os.path.join(BASE_DIR, "config", "registry.yaml")]

    for fpath in files:
        with open(fpath, "r", encoding="utf-8-sig") as f:
            data = yaml.safe_load(f) or {}

        # 1. Format Service-Centric (tools: ...)
        if "tools" in data:
            for t_name, meta in data["tools"].items():
                entry = new_tool_reg.setdefault(t_name, {"primitive_mod": [], "primitive_chk": []})
                if "primitive_mod" in meta:
                    entry["primitive_mod"].extend(meta["primitive_mod"])
                    entry["primitive_chk"].extend(meta.get("primitive_chk", []))
                elif "primitive" in meta:
                    p = meta["primitive"]
                    if p.startswith("read:"):
                        entry["primitive_mod"].append(p)
                    else:
                        entry["primitive_chk"].append(p)
                if "description" in meta and meta["description"]:
                    entry["description"] = str(meta["description"]).strip()

        # 2. Format Type-Centric (primitives: { tag: [outils] })
        if "primitives" in data:
            for prim, tools_list in data["primitives"].items():
                for t_name in tools_list:
                    entry = new_tool_reg.setdefault(t_name, {"primitive_mod": [], "primitive_chk": []})
                    if prim.startswith("read:") or prim.startswith("env:"):
                        if prim not in entry["primitive_mod"]:
                            entry["primitive_mod"].append(prim)
                    else:
                        if prim not in entry["primitive_chk"]:
                            entry["primitive_chk"].append(prim)

        # 3. Format Authoritative Descriptions (descriptions: { tool_name: "Canonical description" })
        if "descriptions" in data and isinstance(data["descriptions"], dict):
            for t_name, desc_text in data["descriptions"].items():
                if desc_text:
                    entry = new_tool_reg.setdefault(t_name, {"primitive_mod": [], "primitive_chk": []})
                    entry["description"] = str(desc_text).strip()

        # 4. Format Zone-Centric (resources: ...)
        if "resources" in data and isinstance(data["resources"], dict):
            for z_name, z_meta in data["resources"].items():
                if isinstance(z_meta, dict):
                    new_res_zones.append({
                        "name": z_meta.get("name", z_name),
                        "match": z_meta.get("match", {}),
                        "match_content": z_meta.get("match_content", {}),
                        "override_mod": z_meta.get("override_mod", []),
                        "override_chk": z_meta.get("override_chk", []),
                        "applies_to": z_meta.get("applies_to", [])
                    })

    # Atomic re-binding of global registries
    TOOL_REGISTRY = new_tool_reg
    RESOURCE_ZONES = new_res_zones
    INVARIANTS_REGISTRY = new_inv_reg
    GLOBAL_ACTIVE_INVARIANTS = new_global_active

LAST_REGISTRY_MTIME = 0.0
LAST_REGISTRY_CHECK = 0.0

def get_latest_registry_mtime() -> float:
    reg_dir = os.path.join(BASE_DIR, "config", "registry.d")
    files = glob.glob(os.path.join(reg_dir, "*.yaml")) if os.path.exists(reg_dir) else []
    inv_file = os.path.join(BASE_DIR, "config", "invariants.yaml")
    if os.path.exists(inv_file):
        files.append(inv_file)
    return max([os.path.getmtime(f) for f in files], default=0.0)

def check_registry_freshness():
    global LAST_REGISTRY_MTIME, LAST_REGISTRY_CHECK
    now = time.monotonic()
    if now - LAST_REGISTRY_CHECK < 2.0:
        return
    LAST_REGISTRY_CHECK = now
    current_mtime = get_latest_registry_mtime()
    if current_mtime > LAST_REGISTRY_MTIME:
        compile_registry()
        LAST_REGISTRY_MTIME = current_mtime

compile_registry()
LAST_REGISTRY_MTIME = get_latest_registry_mtime()

MAX_SESSIONS = 10_000
SESSION_STORE: OrderedDict[str, int] = OrderedDict()
THOUGHT_SIGNATURE_CACHE: OrderedDict[str, dict] = OrderedDict()

def resolve_primitives(tool_name: str, args: dict, result_content: str, regime: str) -> tuple[list[str], list[str], str | None]:
    """Resolve cyber primitives according to the active security regime (blackbox or resource_aware)."""
    base_meta = TOOL_REGISTRY.get(tool_name, {"primitive_mod": [], "primitive_chk": []})
    p_mod = list(base_meta.get("primitive_mod", []))
    p_chk = list(base_meta.get("primitive_chk", []))
    matched_zone = None

    # In optional resource_aware V2 regime, evaluate declarative zones (call arguments + tool output)
    if regime == "resource_aware" and RESOURCE_ZONES:
        for zone in RESOURCE_ZONES:
            if tool_name in zone.get("applies_to", []):
                match_args = zone.get("match", {})
                is_match = True

                # 1. Argument verification (Universal Quantification over multi-recipient lists/strings)
                if match_args:
                    for param_key, pattern in match_args.items():
                        raw_val = args.get(param_key)
                        if raw_val is None:
                            is_match = False
                            break

                        # Extract individual elements from list, tuple, or comma/semicolon-separated string
                        if isinstance(raw_val, (list, tuple)):
                            elements = [str(x).strip() for x in raw_val if str(x).strip()]
                        elif isinstance(raw_val, str) and ("," in raw_val or ";" in raw_val):
                            elements = [x.strip() for x in re.split(r"[,;]", raw_val) if x.strip()]
                        else:
                            elements = [str(raw_val).strip()]

                        if not elements:
                            is_match = False
                            break

                        # Universal quantification: EVERY element must satisfy the zone predicate
                        if not all(re.search(pattern, elem, re.IGNORECASE) for elem in elements):
                            is_match = False
                            break

                # 2. Returned tool content verification (bounded L7 header check against spoofing)
                match_content = zone.get("match_content", {})
                if is_match and match_content:
                    if isinstance(match_content, str):
                        # Bounded scan over the first 10k bytes
                        if not re.search(match_content, result_content[:10_000], re.IGNORECASE):
                            is_match = False
                    elif isinstance(match_content, dict):
                        parsed_json = None
                        try:
                            parsed_json = json.loads(result_content)
                        except Exception:
                            parsed_json = None

                        for field_name, pattern in match_content.items():
                            val = ""
                            check_fields = [field_name]
                            if field_name == "sender": check_fields.append("from")
                            elif field_name == "from": check_fields.append("sender")

                            if isinstance(parsed_json, dict):
                                # Inspect root object or nested metadata dictionary
                                for cf in check_fields:
                                    if cf in parsed_json:
                                        val = str(parsed_json.get(cf, ""))
                                        break
                                    elif "metadata" in parsed_json and isinstance(parsed_json["metadata"], dict) and cf in parsed_json["metadata"]:
                                        val = str(parsed_json["metadata"].get(cf, ""))
                                        break
                            else:
                                # For plain text, match ONLY strict line-start header within the first 2,000 bytes
                                for cf in check_fields:
                                    hdr_match = re.search(rf"(?mi)^\s*{re.escape(cf)}:\s*['\"]?([^\r\n'\"]+)", result_content[:2_000])
                                    if hdr_match:
                                        val = hdr_match.group(1).strip()
                                        break

                            if not val or not re.search(pattern, val, re.IGNORECASE):
                                is_match = False
                                break

                if is_match:
                    p_mod = list(zone.get("override_mod", p_mod))
                    p_chk = list(zone.get("override_chk", p_chk))
                    matched_zone = zone.get("name")
                    break

    return p_mod, p_chk, matched_zone

def find_invariant_violation(state: int, p_chk: list[str], active_invariants: set[str]) -> tuple[str, str] | None:
    """Return (invariant_name, denied_primitive) for the first violated TTC invariant, else None."""
    for inv_id, inv in INVARIANTS_REGISTRY.items():
        if inv_id in active_invariants and (state & inv["req_mask"]) == inv["req_mask"]:
            for deny in inv["deny_primitives"]:
                if (deny.endswith("*") and any(tag.startswith(deny[:-1]) for tag in p_chk)) or (deny in p_chk):
                    return inv["name"], deny
    return None

def check_admin_auth(request: Request) -> bool:
    """Validate X-Admin-Key or Authorization Bearer header if ADMIN_API_KEY is configured."""
    if not ADMIN_API_KEY:
        return True
    auth = request.headers.get("x-admin-key") or request.headers.get("authorization", "").replace("Bearer ", "").strip()
    return auth == ADMIN_API_KEY

# ==============================================================================
# ADMIN CONTROL PLANE: DYNAMIC EXTERNAL POLICY TAGS (QUARANTINE, READ-ONLY, ETC.)
# ==============================================================================
@app.get("/v1/admin/tags")
async def get_admin_tags():
    """Inspect active global and session-specific external policy tags in real time."""
    active_sessions = {
        sid: format_tag_bits(mask)
        for sid, mask in list(SESSION_EXT_TAGS.items())[-50:]
        if mask != 0
    }
    return JSONResponse({
        "status": "ok",
        "global_tags": format_tag_bits(GLOBAL_EXT_TAGS),
        "global_mask": GLOBAL_EXT_TAGS,
        "global_mask_bin": bin(GLOBAL_EXT_TAGS),
        "quarantine_active": bool(GLOBAL_EXT_TAGS & BIT_EXT_QUARANTINE),
        "session_tags": active_sessions,
        "total_active_sessions": len(SESSION_STORE)
    })

@app.post("/v1/admin/tags")
async def update_admin_tags(request: Request):
    """Set, add, or clear external tags globally or per-session."""
    global GLOBAL_EXT_TAGS
    if not check_admin_auth(request):
        return JSONResponse(status_code=403, content={"error": "Unauthorized: Invalid X-Admin-Key"})

    payload = await request.json()
    target = payload.get("target", "global").strip()
    action = payload.get("action", "set").strip().lower()
    tags = payload.get("tags", [])
    mask = parse_tag_bits(tags)

    if target == "global":
        if action == "add":
            GLOBAL_EXT_TAGS |= mask
        elif action == "remove":
            GLOBAL_EXT_TAGS &= ~mask
        elif action in ["clear", "reset"]:
            GLOBAL_EXT_TAGS = 0
        else:  # "set"
            GLOBAL_EXT_TAGS = mask

        active = format_tag_bits(GLOBAL_EXT_TAGS)
        print(f" [*] [ADMIN CONTROL PLANE] Global external tags updated -> {active} (mask: {bin(GLOBAL_EXT_TAGS)})", flush=True)
        return JSONResponse({
            "status": "ok",
            "target": "global",
            "active_tags": active,
            "mask": GLOBAL_EXT_TAGS,
            "mask_bin": bin(GLOBAL_EXT_TAGS),
            "quarantine_active": bool(GLOBAL_EXT_TAGS & BIT_EXT_QUARANTINE)
        })
    else:
        session_id = target
        curr_mask = SESSION_EXT_TAGS.get(session_id, 0)
        if action == "add":
            curr_mask |= mask
        elif action == "remove":
            curr_mask &= ~mask
        elif action in ["clear", "reset"]:
            curr_mask = 0
        else:  # "set"
            curr_mask = mask

        if curr_mask != 0:
            SESSION_EXT_TAGS[session_id] = curr_mask
            SESSION_EXT_TAGS.move_to_end(session_id)
            if len(SESSION_EXT_TAGS) > MAX_SESSIONS:
                SESSION_EXT_TAGS.popitem(last=False)
        else:
            SESSION_EXT_TAGS.pop(session_id, None)

        active = format_tag_bits(curr_mask)
        print(f" [*] [ADMIN CONTROL PLANE] Session '{session_id}' external tags updated -> {active} (mask: {bin(curr_mask)})", flush=True)
        return JSONResponse({
            "status": "ok",
            "target": session_id,
            "active_tags": active,
            "mask": curr_mask,
            "mask_bin": bin(curr_mask),
            "quarantine_active": bool(curr_mask & BIT_EXT_QUARANTINE)
        })

@app.delete("/v1/admin/tags")
async def delete_admin_tags(request: Request):
    """Clear all global external tags and optionally reset all session overrides."""
    global GLOBAL_EXT_TAGS
    if not check_admin_auth(request):
        return JSONResponse(status_code=403, content={"error": "Unauthorized: Invalid X-Admin-Key"})

    GLOBAL_EXT_TAGS = 0
    clear_sessions = request.query_params.get("all_sessions", "false").lower() in ["true", "1", "yes"]
    if clear_sessions:
        SESSION_EXT_TAGS.clear()
    print(" [*] [ADMIN CONTROL PLANE] Global external tags cleared to 0b0.", flush=True)
    return JSONResponse({
        "status": "ok",
        "message": "Global external tags reset",
        "all_sessions_cleared": clear_sessions
    })

# ==============================================================================
# ADMIN CONTROL PLANE: DYNAMIC DECLARATIVE TTC INVARIANTS SELECTION
# ==============================================================================
@app.get("/v1/admin/policies")
async def get_admin_policies():
    """Inspect all registered Toxic Tool Combination invariants and their global/session activation status."""
    return JSONResponse({
        "status": "ok",
        "available_policies": [
            {
                "id": inv["id"],
                "name": inv["name"],
                "description": inv["description"],
                "requires": [
                    name for mask, name in [(BIT_TAINTED, "TAINTED"), (BIT_CONFIDENTIAL, "CONFIDENTIAL")]
                    if (inv["req_mask"] & mask) == mask
                ],
                "deny_primitives": inv["deny_primitives"],
                "default_enabled": inv["enabled"],
                "active_globally": inv["id"] in GLOBAL_ACTIVE_INVARIANTS
            }
            for inv in INVARIANTS_REGISTRY.values()
        ],
        "global_active_policies": list(GLOBAL_ACTIVE_INVARIANTS),
        "total_registered": len(INVARIANTS_REGISTRY)
    })

@app.post("/v1/admin/policies")
async def update_admin_policies(request: Request):
    """Enable or disable specific TTC invariants globally or per session."""
    if not check_admin_auth(request):
        return JSONResponse(status_code=403, content={"error": "Unauthorized: Invalid X-Admin-Key"})

    payload = await request.json()
    target = payload.get("target", "global").strip()
    action = payload.get("action", "enable").strip().lower()  # enable, disable, set, reset
    policies = set(payload.get("policies", []))

    if target == "global":
        if action == "enable":
            GLOBAL_ACTIVE_INVARIANTS.update(policies)
        elif action == "disable":
            GLOBAL_ACTIVE_INVARIANTS.difference_update(policies)
        elif action == "reset":
            GLOBAL_ACTIVE_INVARIANTS.clear()
            GLOBAL_ACTIVE_INVARIANTS.update({k for k, v in INVARIANTS_REGISTRY.items() if v["enabled"]})
        else:  # "set"
            GLOBAL_ACTIVE_INVARIANTS.clear()
            GLOBAL_ACTIVE_INVARIANTS.update(policies)

        print(f" [*] [ADMIN CONTROL PLANE] Global active TTC policies updated -> {list(GLOBAL_ACTIVE_INVARIANTS)}", flush=True)
        return JSONResponse({"status": "ok", "target": "global", "active_policies": list(GLOBAL_ACTIVE_INVARIANTS)})
    else:
        session_id = target
        curr = SESSION_ACTIVE_INVARIANTS.setdefault(session_id, set(GLOBAL_ACTIVE_INVARIANTS))
        if action == "enable":
            curr.update(policies)
        elif action == "disable":
            curr.difference_update(policies)
        elif action == "reset":
            SESSION_ACTIVE_INVARIANTS.pop(session_id, None)
            return JSONResponse({"status": "ok", "target": session_id, "active_policies": list(GLOBAL_ACTIVE_INVARIANTS), "reset": True})
        else:  # "set"
            curr.clear()
            curr.update(policies)

        if len(SESSION_ACTIVE_INVARIANTS) > MAX_SESSIONS:
            SESSION_ACTIVE_INVARIANTS.popitem(last=False)
        print(f" [*] [ADMIN CONTROL PLANE] Session '{session_id}' active TTC policies updated -> {list(curr)}", flush=True)
        return JSONResponse({"status": "ok", "target": session_id, "active_policies": list(curr)})

@app.post("/v1/chat/completions")
async def intercept_chat(request: Request):
    check_registry_freshness()
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Malformed JSON payload: failed to parse request body"})
    if not isinstance(payload, dict):
        return JSONResponse(status_code=400, content={"error": "Invalid JSON: request body must be a JSON object"})
    if payload.get("stream"):
        return JSONResponse(status_code=400, content={"error": "stream=true unsupported: downstream barrier requires a complete JSON response"})

    # Isolate kernel timing strictly to FSM state resolution & MTM schema projection
    t_start = time.perf_counter_ns()

    session_id = request.headers.get("x-session-id")
    if not session_id:
        if STRICT_MODE:
            return JSONResponse(status_code=400, content={"error": "X-Session-ID required in strict mode"})
        session_id = f"ephemeral_{uuid.uuid4().hex[:8]}"
    parent_session_id = request.headers.get("x-parent-session-id")
    parent_fsm_hdr = (
        request.headers.get("x-parent-fsm-state") or 
        request.headers.get("x-inherited-taint")
    )
    defense_mode = "mtm_gateway" if STRICT_MODE else (request.headers.get("x-defense-mode") or "mtm_gateway")
    masking_off = (request.headers.get("x-masking") or "").strip().lower() in ("off", "false", "0") or defense_mode == "barrier_only"
    gateway_active = defense_mode in ("mtm_gateway", "barrier_only")
    security_regime = "blackbox" if STRICT_MODE else (request.headers.get("x-security-regime") or "blackbox")
    refusal_format = request.headers.get("x-refusal-format") or "structured_200"
    batch_policy = "causal_prospective" if STRICT_MODE else (request.headers.get("x-batch-policy") or "causal_prospective")

    state = SESSION_STORE.setdefault(session_id, BIT_CLEAN)
    if parent_session_id and parent_session_id in SESSION_STORE:
        state |= SESSION_STORE[parent_session_id]
    if parent_fsm_hdr:
        try:
            state |= int(parent_fsm_hdr.split()[0], 0)
        except (ValueError, IndexError):
            pass

    if parent_session_id or parent_fsm_hdr:
        print(f" [*] [IFC TAINT INHERITANCE] Session '{session_id}' inherited state {bin(state)} (Parent: '{parent_session_id}', Header State: '{parent_fsm_hdr}')", flush=True)

    # 1. Parse completed tool execution returns (role: "tool") and compute monotonic taint join
    # Index tool_call_id -> (function name, arguments) for OpenAI REST schema compliance
    call_id_to_name = {}
    call_id_to_args = {}
    for msg in payload.get("messages", []):
        if msg.get("role") == "assistant":
            for call in msg.get("tool_calls") or []:
                cid = call.get("id")
                cname = call.get("function", {}).get("name")
                raw_args = call.get("function", {}).get("arguments", "{}")
                try:
                    cargs = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                except (json.JSONDecodeError, TypeError):
                    cargs = {}
                if cid:
                    if cname:
                        call_id_to_name[cid] = cname
                    call_id_to_args[cid] = cargs
                    # Restore upstream thought signature / extra_content stripped by client SDK
                    if cid in THOUGHT_SIGNATURE_CACHE:
                        for k, v in THOUGHT_SIGNATURE_CACHE[cid].items():
                            if not call.get(k):
                                call[k] = copy.deepcopy(v)

    matched_zones = []
    for msg in payload.get("messages", []):
        if msg.get("role") == "tool":
            cid = msg.get("tool_call_id")
            t_name = call_id_to_name.get(cid) or msg.get("name")
            if not t_name:
                continue
            args = call_id_to_args.get(cid, {})
            result_content = str(msg.get("content", ""))

            p_mod, _, z_name = resolve_primitives(t_name, args, result_content, security_regime)
            if z_name and z_name not in matched_zones:
                matched_zones.append(z_name)

            if "read:untrusted" in p_mod:
                state |= BIT_TAINTED
            if "read:confidential" in p_mod:
                state |= BIT_CONFIDENTIAL

    SESSION_STORE[session_id] = state
    SESSION_STORE.move_to_end(session_id)
    if len(SESSION_STORE) > MAX_SESSIONS:
        SESSION_STORE.popitem(last=False)
    if parent_session_id:
        SESSION_STORE[parent_session_id] = SESSION_STORE.get(parent_session_id, BIT_CLEAN) | state
        SESSION_STORE.move_to_end(parent_session_id)
        if len(SESSION_STORE) > MAX_SESSIONS:
            SESSION_STORE.popitem(last=False)
    is_trifecta = (state & BIT_TRIFECTA) == BIT_TRIFECTA
    is_tainted = (state & BIT_TAINTED) == BIT_TAINTED

    # Resolve active external policy tags: Global OR Session OR Request Header
    hdr_ext_tags = request.headers.get("x-external-tags")
    req_ext_mask = parse_tag_bits(hdr_ext_tags) if hdr_ext_tags else 0
    session_ext_mask = SESSION_EXT_TAGS.get(session_id, 0)
    active_ext_mask = GLOBAL_EXT_TAGS | session_ext_mask | req_ext_mask
    active_ext_labels = format_tag_bits(active_ext_mask)

    # Resolve active TTC Invariant policies: Global -> Session override -> Request Header override
    req_ttc_header = request.headers.get("x-ttc-policies")
    if req_ttc_header:
        hdr_clean = req_ttc_header.strip().lower()
        if hdr_clean in ["all", "*"]:
            active_invariants = set(INVARIANTS_REGISTRY.keys())
        elif hdr_clean in ["none", "off", "0"]:
            active_invariants = set()
        else:
            active_invariants = {p.strip().lower() for p in hdr_clean.split(",") if p.strip()}
    elif session_id in SESSION_ACTIVE_INVARIANTS:
        active_invariants = SESSION_ACTIVE_INVARIANTS[session_id]
    else:
        active_invariants = GLOBAL_ACTIVE_INVARIANTS

    allowed_tool_names = set()
    if "tools" in payload and payload["tools"]:
        for t in payload["tools"]:
            name = t.get("function", {}).get("name")
            if name:
                allowed_tool_names.add(name)

    original_tools_count = len(payload.get("tools", []))
    masked_tool_names = []
    pinned_tool_names = []

    # 2. Upstream Monotone Tool Masking (MTM)
    if gateway_active and not masking_off and "tools" in payload:
        # Check emergency quarantine first (Strict MTM: 0 tools forwarded)
        if (active_ext_mask & BIT_EXT_QUARANTINE):
            masked_tool_names = [
                t.get("function", {}).get("name") 
                for t in payload.get("tools", []) 
                if t.get("function", {}).get("name")
            ]
            payload.pop("tools", None)
            payload.pop("tool_choice", None)
            allowed_tool_names = set()
            print(f" [*] [CIRCUIT BREAKER - QUARANTINE ACTIVE] All {original_tools_count} tools stripped! Agent entered Conversational Parole mode.", flush=True)
        else:
            # Auto-reload registry if any incoming tool is not yet indexed
            for t in payload["tools"]:
                tn = t.get("function", {}).get("name")
                if tn and tn not in TOOL_REGISTRY:
                    compile_registry()
                    break

            filtered_tools = []
            for t in payload["tools"]:
                t_name = t.get("function", {}).get("name")
                if not t_name or t_name not in TOOL_REGISTRY:
                    continue

                p_mod, p_chk, _ = resolve_primitives(t_name, {}, "", security_regime)

                # External Policy Tag Invariants (Strict Monotonic Lattice Meet: P_eff = P_internal & P_external)
                if (active_ext_mask & BIT_EXT_NO_EGRESS) and "egress:outside" in p_chk:
                    masked_tool_names.append(t_name)
                    continue

                if (active_ext_mask & BIT_EXT_NO_READ) and any(tag.startswith("read:") for tag in p_mod):
                    masked_tool_names.append(t_name)
                    continue

                if (active_ext_mask & BIT_EXT_NO_WRITE) and any(
                    tag.startswith("write:") or tag.startswith("exec:") or tag.startswith("iam:") or tag.startswith("delete:")
                    for tag in p_chk
                ):
                    masked_tool_names.append(t_name)
                    continue

                # Dynamic Toxic Tool Combination (TTC) Invariants Evaluation
                if find_invariant_violation(state, p_chk, active_invariants) is not None:
                    masked_tool_names.append(t_name)
                    continue

                # Authoritative Schema Pinning (ASP): Neutralize MCP metadata injection & Rug Pulls
                tool_meta = TOOL_REGISTRY.get(t_name, {})
                auth_desc = tool_meta.get("description")
                if auth_desc and "function" in t:
                    inc_desc = t["function"].get("description", "")
                    if inc_desc != auth_desc:
                        t = copy.deepcopy(t)
                        t["function"]["description"] = auth_desc
                        pinned_tool_names.append(t_name)
                        print(f" [*] [AUTHORITATIVE SCHEMA PINNING] Tool '{t_name}' description was modified upstream/MCP. Pinned back to offline canonical definition (Rug Pull cancelled).", flush=True)

                filtered_tools.append(t)

            payload["tools"] = filtered_tools
            allowed_tool_names = {t.get("function", {}).get("name") for t in filtered_tools if t.get("function", {}).get("name")}
            if not payload["tools"]:
                payload.pop("tools", None)
                payload.pop("tool_choice", None)

    state_labels = []
    if is_tainted: state_labels.append("TAINTED")
    if (state & BIT_CONFIDENTIAL) == BIT_CONFIDENTIAL: state_labels.append("CONFIDENTIAL")
    if is_trifecta: state_labels.append("TRIFECTA")
    state_str = "+".join(state_labels) if state_labels else "CLEAN"

    if matched_zones and security_regime == "resource_aware":
        print(f" [*] [RESOURCE-AWARE V2] Policy Zones Matched: {matched_zones}", flush=True)

    if gateway_active:
        if masked_tool_names:
            print(f" [*] [MTM GATEWAY] FSM Pruning ({bin(state)} {state_str}) : {len(payload.get('tools', []))}/{original_tools_count} tools forwarded | PRUNED: {masked_tool_names}", flush=True)
        else:
            print(f" [*] [MTM GATEWAY] FSM ({bin(state)} {state_str}) : {len(payload.get('tools', []))}/{original_tools_count} tools forwarded (full schema)", flush=True)

    t_fsm_us = (time.perf_counter_ns() - t_start) / 1_000.0

    target_model = payload.get("model") or UPSTREAM_MODEL
    upstream_url, headers, is_cloud = resolve_upstream(target_model)
    if "openrouter" in upstream_url:
        if target_model.lower().strip() in OPENROUTER_SLUG_MAP:
            target_model = OPENROUTER_SLUG_MAP[target_model.lower().strip()]
        headers["x-session-id"] = request.headers.get("x-cache-session-id") or session_id
    payload["model"] = target_model

    injected_reasoning_effort = False
    if is_cloud:
        payload.pop("options", None)
        if "reasoning_effort" not in payload and REASONING_EFFORT:
            payload["reasoning_effort"] = REASONING_EFFORT
            injected_reasoning_effort = True
        if "openrouter" in upstream_url and "reasoning" not in payload and REASONING_EFFORT:
            payload["reasoning"] = {"effort": REASONING_EFFORT}
    else:
        payload.pop("reasoning_effort", None)
        payload.pop("reasoning", None)
        if "options" not in payload:
            payload["options"] = {"num_ctx": 16384}

    global HTTP_CLIENT
    client = HTTP_CLIENT or httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=15.0))
    upstream_resp = None
    for attempt_idx in range(3):
        try:
            upstream_resp = await client.post(upstream_url, json=payload, headers=headers)
        except httpx.ConnectError as e:
            if is_cloud and attempt_idx < 2:
                import asyncio
                print(f" [~] [UPSTREAM CONNECT RETRY] Retrying ({attempt_idx + 1}/2) for {upstream_url}...", flush=True)
                await asyncio.sleep(1.5 * (attempt_idx + 1))
                continue
            err_msg = f"Cannot connect to upstream LLM at {upstream_url}. If using local models (e.g. {target_model}), ensure Ollama is running ('ollama serve'). Details: {e}"
            print(f" [!] [UPSTREAM CONNECTION ERROR] {err_msg}", flush=True)
            return JSONResponse(status_code=502, content={"error": err_msg})
        except httpx.TimeoutException as e:
            if is_cloud and attempt_idx < 2:
                import asyncio
                await asyncio.sleep(1.5 * (attempt_idx + 1))
                continue
            err_msg = f"Upstream LLM timeout at {upstream_url} after 300s ({target_model}): {e}"
            print(f" [!] [UPSTREAM TIMEOUT] {err_msg}", flush=True)
            return JSONResponse(status_code=504, content={"error": err_msg})
        except Exception as e:
            if is_cloud and attempt_idx < 2:
                import asyncio
                await asyncio.sleep(1.5 * (attempt_idx + 1))
                continue
            err_msg = f"Unexpected error forwarding to upstream LLM ({upstream_url}): {e}"
            print(f" [!] [UPSTREAM UNEXPECTED ERROR] {err_msg}", flush=True)
            return JSONResponse(status_code=502, content={"error": err_msg})

        if upstream_resp.status_code == 400 and injected_reasoning_effort and "reasoning_effort" in payload:
            payload.pop("reasoning_effort", None)
            injected_reasoning_effort = False
            continue
        if is_cloud and upstream_resp.status_code in (429, 500, 502, 503, 504) and attempt_idx < 2:
            import asyncio
            print(f" [~] [UPSTREAM TRANSIENT {upstream_resp.status_code}] Retrying ({attempt_idx + 1}/2) for {target_model}...", flush=True)
            await asyncio.sleep(2.0 * (attempt_idx + 1))
            continue
        break

    if upstream_resp.status_code != 200:
        print(f" [!] [UPSTREAM ERROR {upstream_resp.status_code} ({target_model} -> {upstream_url})] {upstream_resp.text}", flush=True)
        try:
            err_json = upstream_resp.json()
        except Exception:
            err_json = {"error": upstream_resp.text}
        return JSONResponse(status_code=upstream_resp.status_code, content=err_json)
    resp_data = upstream_resp.json()

    # Cache vendor-specific tool call fields (e.g. Gemini 3.x thought signatures in extra_content)
    if "choices" in resp_data:
        for ch in resp_data.get("choices", []):
            msg = ch.get("message", {})
            for tc in msg.get("tool_calls") or []:
                tc_id = tc.get("id")
                if tc_id:
                    extra_fields = {k: v for k, v in tc.items() if k not in ("id", "type", "function")}
                    if extra_fields:
                        THOUGHT_SIGNATURE_CACHE[tc_id] = copy.deepcopy(extra_fields)
                        THOUGHT_SIGNATURE_CACHE.move_to_end(tc_id)
                        if len(THOUGHT_SIGNATURE_CACHE) > MAX_SESSIONS:
                            THOUGHT_SIGNATURE_CACHE.popitem(last=False)

    # 3. Fail-Closed Downstream Barrier (Strict Default-Deny + In-Flight Race Condition Defense)
    blocked_call_names: list[str] = []
    attempted_call_names: list[str] = []
    if "choices" in resp_data and resp_data["choices"]:
        raw_tcs = resp_data["choices"][0].get("message", {}).get("tool_calls") or []
        attempted_call_names = [
            c.get("function", {}).get("name")
            for c in raw_tcs
            if c.get("function", {}).get("name")
        ]
    if gateway_active and "choices" in resp_data:
        choice = resp_data["choices"][0]
        tool_calls = choice.get("message", {}).get("tool_calls", [])
        if tool_calls:
            # Re-read active external tags dynamically at this exact microsecond to mitigate in-flight race conditions
            current_ext_mask = GLOBAL_EXT_TAGS | SESSION_EXT_TAGS.get(session_id, 0) | req_ext_mask
            # Compute Prospective Batch Union according to batch_policy:
            # - causal_prospective (default): prospective union strictly when session is already tainted (is_tainted)
            # - acausal_union: unconditional prospective union even at clean Turn 1 (q_taint == 0)
            # - pre_turn_static (SkillGuard-style): evaluates strictly against start-of-turn state q_k
            # - topological_linear: updates running state sequentially in JSON array order
            prospective_state = state
            if batch_policy in ("causal_prospective", "acausal_union") and (is_tainted or batch_policy == "acausal_union"):
                for c_pre in tool_calls:
                    tn_pre = c_pre.get("function", {}).get("name")
                    if tn_pre and tn_pre in TOOL_REGISTRY:
                        raw_pre = c_pre.get("function", {}).get("arguments", "{}")
                        try:
                            cargs_pre = json.loads(raw_pre) if isinstance(raw_pre, str) else ({} if raw_pre is None else raw_pre)
                        except Exception:
                            cargs_pre = {}
                        if isinstance(cargs_pre, dict):
                            p_mod_pre, _, _ = resolve_primitives(tn_pre, cargs_pre, "", security_regime)
                            if "read:untrusted" in p_mod_pre:
                                prospective_state |= BIT_TAINTED
                            if "read:confidential" in p_mod_pre:
                                prospective_state |= BIT_CONFIDENTIAL

            running_linear_state = state
            valid_calls = []
            for c in tool_calls:
                t_name = c.get("function", {}).get("name")
                eval_state = running_linear_state if batch_policy == "topological_linear" else prospective_state
                
                reason = None
                if (current_ext_mask & BIT_EXT_QUARANTINE):
                    reason = f"Tool '{t_name}' blocked: Emergency Quarantine circuit-breaker active (zero tools permitted)"
                elif t_name not in allowed_tool_names:
                    reason = f"Tool '{t_name}' absent from allowed schema (pruned by MTM or hallucinated)"
                elif t_name not in TOOL_REGISTRY:
                    reason = f"Tool '{t_name}' uncataloged in cyber registry"
                else:
                    raw_args = c.get("function", {}).get("arguments", "{}")
                    try:
                        cargs = json.loads(raw_args) if isinstance(raw_args, str) else ({} if raw_args is None else raw_args)
                        if not isinstance(cargs, dict):
                            reason = "Malformed non-object JSON arguments (fail-closed)"
                            cargs = None
                    except Exception:
                        reason = "Malformed JSON arguments (fail-closed)"
                        cargs = None

                    if cargs is not None:
                        p_mod_spec, p_chk_spec, _ = resolve_primitives(t_name, cargs, "", security_regime)
                        
                        # Re-verify external policy tag constraints downstream
                        if (current_ext_mask & BIT_EXT_NO_EGRESS) and "egress:outside" in p_chk_spec:
                            reason = f"External policy violation: 'no_egress' tag active for '{t_name}'"
                        elif (current_ext_mask & BIT_EXT_NO_READ) and any(tag.startswith("read:") for tag in p_mod_spec):
                            reason = f"External policy violation: 'no_read' tag active for '{t_name}'"
                        elif (current_ext_mask & BIT_EXT_NO_WRITE) and any(
                            tag.startswith("write:") or tag.startswith("exec:") or tag.startswith("iam:") or tag.startswith("delete:")
                            for tag in p_chk_spec
                        ):
                            reason = f"External policy violation: 'read_only' / 'no_write' tag active for '{t_name}'"
                        else:
                            inv_viol = find_invariant_violation(eval_state, p_chk_spec, active_invariants)
                            if inv_viol:
                                inv_name, deny = inv_viol
                                reason = f"Toxic Tool Combination violation ({inv_name}) on '{t_name}' ({deny} forbidden)"

                        if not reason and batch_policy == "topological_linear":
                            if "read:untrusted" in p_mod_spec:
                                running_linear_state |= BIT_TAINTED
                            if "read:confidential" in p_mod_spec:
                                running_linear_state |= BIT_CONFIDENTIAL


                if reason:
                    print(f" [*] [DEFAULT-DENY BARRIER] {reason}", flush=True)
                    if t_name:
                        blocked_call_names.append(t_name)
                    continue

                valid_calls.append(c)

            if not valid_calls:
                if refusal_format == "http_403":
                    return JSONResponse(status_code=403, content={"error": "Error 403 (Forbidden): Operation blocked by reference monitor security policy (MTM invariant / unauthorized tool)."})
                choice["message"].pop("tool_calls", None)
                choice["finish_reason"] = "stop"
                choice["message"]["content"] = "Operation blocked by reference monitor security policy (MTM invariant / unauthorized tool)."
            else:
                choice["message"]["tool_calls"] = valid_calls

    return JSONResponse(
        content=resp_data, 
        headers={
            "X-FSM-Latency-Us": f"{t_fsm_us:.2f}",
            "X-Active-Regime": security_regime,
            "X-TTC-FSM-State": f"{bin(state)} ({state_str})",
            "X-TTC-External-Tags": ",".join(active_ext_labels) if active_ext_labels else "none",
            "X-TTC-Parole-Warning": "TRUE" if (active_ext_mask & BIT_EXT_QUARANTINE) else "FALSE",
            "X-TTC-Masked-Tools": json.dumps(masked_tool_names),
            "X-TTC-Pinned-Tools": json.dumps(pinned_tool_names),
            "X-TTC-Attempted-Calls": json.dumps(attempted_call_names),
            "X-TTC-Blocked-Calls": json.dumps(blocked_call_names),
            "X-TTC-Residual-Call": "TRUE" if blocked_call_names else "FALSE",
            "X-TTC-Active-Count": str(len(payload.get("tools", []))),
            "X-TTC-Total-Count": str(original_tools_count),
            "X-TTC-Matched-Zones": json.dumps(matched_zones)
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
