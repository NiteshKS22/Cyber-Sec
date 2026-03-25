#!/usr/bin/env python3
# ai_worker.py
#
# DFIR-IRIS AI worker (async enrichment):
# - Finds alerts tagged "ai-pending"
# - Claims alert by swapping to "ai-processing" (prevents duplicate work across workers)
# - Runs Ollama triage
# - Updates ONLY: alert_note + alert_tags
# - Finalizes tags: remove ai-processing/ai-pending, add ai-reviewed
#
# Run:
#   export IRIS_BEARER="..."
#   export AI_WORKER_POLL_SECONDS=180
#   python3 /var/ossec/integrations/ai_worker.py >> /var/ossec/logs/ai_worker.log 2>&1 &
#
# Watch:
#   tail -f /var/ossec/logs/ai_worker.log

import os
import time
import json
import re
import requests
import urllib3
from typing import Dict, Any, List, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIG
# ============================================================

IRIS_BASE_URL = os.getenv("IRIS_BASE_URL", "https://<iris_IP>:8443").rstrip("/")
IRIS_BEARER = os.getenv("IRIS_BEARER", "")
VERIFY_SSL = os.getenv("IRIS_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

IRIS_CID_ENV = os.getenv("IRIS_CID", "").strip()
IRIS_CID: Optional[int] = int(IRIS_CID_ENV) if IRIS_CID_ENV.isdigit() else None

POLL_INTERVAL_SECONDS = int(os.getenv("AI_WORKER_POLL_SECONDS", "60"))  # default 1 minutes
PAGE_SIZE = int(os.getenv("AI_WORKER_PAGE_SIZE", "30"))
MAX_ALERTS_PER_CYCLE = int(os.getenv("AI_WORKER_MAX_PER_CYCLE", "10"))

TAG_AI_PENDING = os.getenv("AI_TAG_PENDING", "ai-pending")
TAG_AI_PROCESSING = os.getenv("AI_TAG_PROCESSING", "ai-processing")
TAG_AI_REVIEWED = os.getenv("AI_TAG_REVIEWED", "ai-reviewed")

# Ollama
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://<ollama_ip>:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi4-mini:latest")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "60"))
OLLAMA_MAX_CHARS = int(os.getenv("OLLAMA_MAX_CHARS", "4500"))  # keep smaller for speed
REDACT_SECRETS = os.getenv("OLLAMA_REDACT_SECRETS", "true").lower() in ("1", "true", "yes")

# Circuit breaker (avoid hammering Ollama if it's failing)
OLLAMA_FAIL_LIMIT = int(os.getenv("OLLAMA_FAIL_LIMIT", "5"))
OLLAMA_COOLDOWN_SECONDS = int(os.getenv("OLLAMA_COOLDOWN_SECONDS", "120"))

_last_ollama_fail_ts = 0.0
_ollama_fail_count = 0

if not IRIS_BEARER:
    raise SystemExit("Missing IRIS_BEARER environment variable")

# ============================================================
# REDACTION / SANITIZE
# ============================================================

REDACT_PATTERNS = [
    (re.compile(r'(?i)\b(password|passwd|pwd)\s*[:=]\s*([^\s"\']+)'), r'\1=<REDACTED>'),
    (re.compile(r'(?i)\b(token|api[_-]?key|secret|bearer)\s*[:=]\s*([^\s"\']+)'), r'\1=<REDACTED>'),
    (re.compile(r'(?i)\b(authorization)\s*:\s*bearer\s+([^\s]+)'), r'\1: Bearer <REDACTED>'),
]

def redact_text(s: str) -> str:
    if not s or not isinstance(s, str):
        return ""
    out = s
    for rgx, rep in REDACT_PATTERNS:
        out = rgx.sub(rep, out)
    return out

def sanitize_plain_text(s: str) -> str:
    if not s or not isinstance(s, str):
        return ""
    s = re.sub(r"(?m)^\s*[\*\#>\-]+\s*", "", s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return s.strip()

# ============================================================
# TAG UTIL
# ============================================================

def parse_tags(tag_str: str) -> List[str]:
    if not tag_str or not isinstance(tag_str, str):
        return []
    return [t.strip() for t in tag_str.split(",") if t.strip()]

def join_tags(tags: List[str]) -> str:
    seen = set()
    out = []
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return ",".join(out)

def contains_ai_review(note: str) -> bool:
    if not note:
        return False
    return "AI TRIAGE REVIEW" in note.upper()

# ============================================================
# IRIS API
# ============================================================

def iris_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {IRIS_BEARER}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

def with_cid(url: str) -> str:
    if IRIS_CID is None:
        return url
    if "cid=" in url:
        return url
    join = "&" if "?" in url else "?"
    return f"{url}{join}cid={IRIS_CID}"

def iris_filter_alerts_by_tag(tag: str, per_page: int, page: int) -> List[Dict[str, Any]]:
    url = with_cid(f"{IRIS_BASE_URL}/alerts/filter")
    params = {
        "alert_tags": tag,
        "per_page": per_page,
        "page": page,
        "sort": "desc",
    }
    r = requests.get(url, headers=iris_headers(), params=params, verify=VERIFY_SSL, timeout=20)
    r.raise_for_status()
    data = r.json() or {}

    d = data.get("data") if isinstance(data, dict) else {}
    alerts = d.get("alerts") if isinstance(d, dict) else None

    if isinstance(alerts, list):
        return alerts
    if isinstance(alerts, dict):
        items = alerts.get("items")
        if isinstance(items, list):
            return items
    return []

def iris_update_alert(alert_id: int, updates: Dict[str, Any]) -> bool:
    url = with_cid(f"{IRIS_BASE_URL}/alerts/update/{alert_id}")
    r = requests.post(url, headers=iris_headers(), json=updates, verify=VERIFY_SSL, timeout=20)
    if r.status_code in (200, 201):
        return True
    body = (r.text or "")[:400]
    print(f"[IRIS] update failed alert_id={alert_id} status={r.status_code} body={body}")
    return False

def iris_get_alert_full(alert_id: int) -> Optional[Dict[str, Any]]:
    candidates = [
        f"{IRIS_BASE_URL}/alerts/read/{alert_id}",
        f"{IRIS_BASE_URL}/alerts/{alert_id}",
        f"{IRIS_BASE_URL}/alerts/get/{alert_id}",
    ]
    for u in candidates:
        url = with_cid(u)
        try:
            r = requests.get(url, headers=iris_headers(), verify=VERIFY_SSL, timeout=20)
            if r.status_code != 200:
                continue
            data = r.json() or {}
            if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
                return data["data"]
            if isinstance(data, dict):
                return data
        except Exception:
            continue
    return None

# ============================================================
# OLLAMA
# ============================================================

def compact_for_llm(alert: Dict[str, Any]) -> str:
    # keep small for speed; DO NOT dump huge source_content
    slim = {
        "alert_id": alert.get("alert_id"),
        "alert_title": alert.get("alert_title"),
        "alert_description": alert.get("alert_description"),
        "alert_source": alert.get("alert_source"),
        "alert_source_ref": alert.get("alert_source_ref"),
        "alert_source_event_time": alert.get("alert_source_event_time"),
        "alert_severity_id": alert.get("alert_severity_id"),
        "alert_status_id": alert.get("alert_status_id"),
        "alert_tags": alert.get("alert_tags"),
        "alert_note": (alert.get("alert_note") or "")[:800],
        "alert_source_content": str(alert.get("alert_source_content") or "")[:900],
    }

    txt = json.dumps(slim, ensure_ascii=False)
    if REDACT_SECRETS:
        txt = redact_text(txt)
    if len(txt) > OLLAMA_MAX_CHARS:
        txt = txt[:OLLAMA_MAX_CHARS] + "...(truncated)"
    return txt

def ollama_available() -> bool:
    global _last_ollama_fail_ts, _ollama_fail_count
    if _ollama_fail_count < OLLAMA_FAIL_LIMIT:
        return True
    if (time.time() - _last_ollama_fail_ts) > OLLAMA_COOLDOWN_SECONDS:
        _ollama_fail_count = 0
        return True
    return False

def ollama_triage(alert: Dict[str, Any]) -> Optional[str]:
    global _last_ollama_fail_ts, _ollama_fail_count

    if not ollama_available():
        return None

    compact = compact_for_llm(alert)

    prompt = f"""
You are a senior SOC analyst. Review the alert and produce a plain-text triage note.

OUTPUT RULES:
1) Do NOT use markdown or bullet symbols. Do not use "*", "#", ">", "-" as list markers.
2) Use simple uppercase headings and each item on its own line.
3) Be concise and actionable. Do not invent facts.

REQUIRED FORMAT:
AI SUMMARY:
(one to three short lines)

LIKELY CAUSE OR SCENARIO:
(1 to 4 lines, each starts with 1., 2., 3., 4.)

RECOMMENDED NEXT STEPS:
(1 to 8 lines, each starts with 1., 2., 3., ...)

FALSE POSITIVE CHECKS:
(1 to 4 lines, each starts with 1., 2., 3., 4.)

CONFIDENCE:
(Low, Medium, or High) - one short reason

ALERT (COMPACT JSON):
{compact}
""".strip()

    payload = {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}

    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        if r.status_code != 200:
            _ollama_fail_count += 1
            _last_ollama_fail_ts = time.time()
            print(f"[OLLAMA] HTTP {r.status_code}: {(r.text or '')[:200]}")
            return None

        data = r.json()
        text = data.get("response", "")
        if not isinstance(text, str) or not text.strip():
            _ollama_fail_count += 1
            _last_ollama_fail_ts = time.time()
            return None

        _ollama_fail_count = 0
        return sanitize_plain_text(text)

    except Exception as e:
        _ollama_fail_count += 1
        _last_ollama_fail_ts = time.time()
        print(f"[OLLAMA] error: {e}")
        return None

# ============================================================
# WORK
# ============================================================

def claim_alert(alert_id: int, alert: Dict[str, Any]) -> bool:
    tags = parse_tags(str(alert.get("alert_tags") or ""))
    if TAG_AI_PENDING not in tags:
        return False
    if TAG_AI_PROCESSING in tags or TAG_AI_REVIEWED in tags:
        return False

    new_tags = [t for t in tags if t != TAG_AI_PENDING]
    new_tags.append(TAG_AI_PROCESSING)

    return iris_update_alert(alert_id, {"alert_tags": join_tags(new_tags)})

def finalize_tags(alert_id: int, current_tags_str: str, success: bool) -> bool:
    tags = parse_tags(current_tags_str)
    tags = [t for t in tags if t not in (TAG_AI_PENDING, TAG_AI_PROCESSING)]
    if success:
        if TAG_AI_REVIEWED not in tags:
            tags.append(TAG_AI_REVIEWED)
    else:
        if TAG_AI_PENDING not in tags and TAG_AI_REVIEWED not in tags:
            tags.append(TAG_AI_PENDING)
    return iris_update_alert(alert_id, {"alert_tags": join_tags(tags)})

def process_one_alert(alert_summary: Dict[str, Any]) -> bool:
    alert_id = alert_summary.get("alert_id")
    if not isinstance(alert_id, int):
        return False

    if not claim_alert(alert_id, alert_summary):
        return False

    full = iris_get_alert_full(alert_id) or alert_summary

    note = str(full.get("alert_note") or "")
    if contains_ai_review(note):
        return finalize_tags(alert_id, str(full.get("alert_tags") or ""), success=True)

    ai = ollama_triage(full)
    if not ai:
        finalize_tags(alert_id, str(full.get("alert_tags") or ""), success=False)
        return False

    new_note = (note.strip() + "\n\n" if note.strip() else "")
    new_note += "AI TRIAGE REVIEW (OLLAMA)\n" + ai

    tags_now = str(full.get("alert_tags") or "")
    tags_list = parse_tags(tags_now)
    tags_list = [t for t in tags_list if t not in (TAG_AI_PENDING, TAG_AI_PROCESSING)]
    if TAG_AI_REVIEWED not in tags_list:
        tags_list.append(TAG_AI_REVIEWED)

    updates = {
        "alert_note": new_note,
        "alert_tags": join_tags(tags_list),
    }

    ok = iris_update_alert(alert_id, updates)
    if not ok:
        finalize_tags(alert_id, tags_now, success=False)
        return False

    return True

def run_once() -> None:
    processed = 0
    page = 1

    while processed < MAX_ALERTS_PER_CYCLE:
        alerts = iris_filter_alerts_by_tag(TAG_AI_PENDING, per_page=PAGE_SIZE, page=page)
        if not alerts:
            break

        for a in alerts:
            if processed >= MAX_ALERTS_PER_CYCLE:
                break
            ok = process_one_alert(a)
            processed += 1
            print(f"[AI_WORKER] alert_id={a.get('alert_id')} updated={ok}")

        page += 1

def main_loop() -> None:
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[AI_WORKER] cycle error: {e}")
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    main_loop()
