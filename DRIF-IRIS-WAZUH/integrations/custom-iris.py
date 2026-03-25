#!/usr/bin/env python3
# custom-iris.py
# Wazuh -> DFIR-IRIS (Bearer auth) - FAST forwarder (NO AI)
#
# Features:
#  - Noise reduction (level gate + MITRE/high-signal overrides + allowlists)
#  - Dedup (15 min) + Burst protection (5 min) with SQLite WAL
#  - Smart extraction (Windows Sysmon / Linux Auditd / generic)
#  - Retry logic for IRIS POST
#  - Adds tag ai-pending for async enrichment by ai_worker.py
#
# Wazuh integration expected args:
#   custom-iris.py <alert_file> <iris_bearer_token> <iris_hook_url>
#
# Example hook_url:
#   https://<iris-IP>:8443/alerts/add   (or your correct endpoint)

import sys
import json
import time
import sqlite3
import hashlib
import re
import requests
import urllib3
from typing import Dict, Any, Optional, Tuple, List

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIGURATION
# ============================================================

VERIFY_SSL = False  # True in production with valid certs

# IRIS Mapping
IRIS_CUSTOMER_ID = 1
IRIS_STATUS_ID = 1

# Gating / Noise Control
MIN_WAZUH_LEVEL_TO_FORWARD = 8
FORWARD_IF_MITRE_PRESENT = True
FORWARD_IF_RULE_IN_HIGH_SIGNAL = True

# Deduplication Settings
DEDUP_WINDOW_SECONDS = 15 * 60
BURST_WINDOW_SECONDS = 5 * 60
BURST_MAX_EVENTS = 5

# Connection Settings
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
HTTP_TIMEOUT = 10

# Rules to NEVER send (Noise)
SUPPRESS_RULE_IDS = {
    # "60642",
}

# Rules to ALWAYS send (High Signal)
HIGH_SIGNAL_RULE_IDS = {
    # "92213",
    # "92029",
}

# Agents to Ignore (e.g., Sandbox, Test VM)
SUPPRESS_AGENTS = {
    # "TEST-VM",
}

# Allowlist Patterns (Regex) - If match, DROP.
ALLOWLIST_CMDLINE_PATTERNS = [
    # r".*\\Windows\\System32\\svchost\.exe.*",
]

ALLOWLIST_IMAGE_PATTERNS = [
    # Windows system
    r"C:\\Windows\\System32\\svchost\.exe$",
    r"C:\\Windows\\System32\\WmiPrvSE\.exe$",
    r"C:\\Windows\\System32\\SearchIndexer\.exe$",
    r"C:\\Windows\\System32\\backgroundTaskHost\.exe$",

    # Security tools
    r"C:\\Program Files\\Windows Defender\\MsMpEng\.exe$",
    r"C:\\Program Files \(x86\)\\ossec-agent\\ossec-agent\.exe$",
    r"C:\\Program Files\\SplunkUniversalForwarder\\bin\\splunkd\.exe$",

    # SCCM / management
    r"C:\\Windows\\CCM\\CcmExec\.exe$",
    r"C:\\Windows\\CCM\\.*\.exe$",

    # Browsers / updaters
    r".*\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate\.exe$",
    r".*\\Google\\Update\\GoogleUpdate\.exe$",
]

ALLOWLIST_TARGETFILE_PATTERNS = [
    # Updates & prefetch
    r"C:\\Windows\\SoftwareDistribution\\.*",
    r"C:\\Windows\\Prefetch\\.*\.pf$",

    # Browser cache
    r".*\\AppData\\Local\\Google\\Chrome\\User Data\\.*",
    r".*\\AppData\\Local\\Microsoft\\Edge\\User Data\\.*",

    # Logs
    r"C:\\Windows\\System32\\winevt\\Logs\\.*",
    r"C:\\Windows\\CCM\\Logs\\.*",
]

# Database & Logging paths
DEDUP_DB = "/var/ossec/var/integrations/iris_state.db"
LOG_FILE = "/var/ossec/logs/integrations.log"

# Payload safety: if source content becomes huge, truncate it
MAX_SOURCE_CONTENT_CHARS = 40000

# AI tags (async enrichment)
TAG_AI_PENDING = "ai-pending"

# ============================================================
# LOGGING
# ============================================================

def log(msg: str):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as lf:
            lf.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass

def safe_int(x, default=0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def get_nested(d: Dict[str, Any], keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

# ============================================================
# DB (DEDUP + BURST)
# ============================================================

def db_init():
    try:
        conn = sqlite3.connect(DEDUP_DB, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dedup (
                h TEXT PRIMARY KEY,
                last_seen INTEGER NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS burst (
                k TEXT PRIMARY KEY,
                first_seen INTEGER NOT NULL,
                count INTEGER NOT NULL
            )
        """)
        conn.commit()
        return conn
    except Exception as e:
        log(f"[DB_ERR] Init failed: {e}")
        return None

def is_duplicate(conn, h: str, now_ts: int) -> bool:
    if not conn:
        return False
    try:
        cur = conn.cursor()
        cur.execute("SELECT last_seen FROM dedup WHERE h=?", (h,))
        row = cur.fetchone()
        if row and (now_ts - row[0]) < DEDUP_WINDOW_SECONDS:
            return True
        cur.execute("INSERT OR REPLACE INTO dedup(h,last_seen) VALUES(?,?)", (h, now_ts))
        conn.commit()
    except Exception as e:
        log(f"[DB_ERR] Dedup check failed: {e}")
    return False

def burst_suppressed(conn, key: str, now_ts: int) -> bool:
    if not conn:
        return False
    try:
        cur = conn.cursor()
        cur.execute("SELECT first_seen, count FROM burst WHERE k=?", (key,))
        row = cur.fetchone()

        if not row:
            cur.execute("INSERT OR REPLACE INTO burst(k, first_seen, count) VALUES(?,?,?)", (key, now_ts, 1))
            conn.commit()
            return False

        first_seen, count = row
        if (now_ts - first_seen) > BURST_WINDOW_SECONDS:
            cur.execute("INSERT OR REPLACE INTO burst(k, first_seen, count) VALUES(?,?,?)", (key, now_ts, 1))
            conn.commit()
            return False

        count += 1
        cur.execute("INSERT OR REPLACE INTO burst(k, first_seen, count) VALUES(?,?,?)", (key, first_seen, count))
        conn.commit()

        return count > BURST_MAX_EVENTS
    except Exception as e:
        log(f"[DB_ERR] Burst check failed: {e}")
        return False

# ============================================================
# EXTRACTION / FILTERS
# ============================================================

def has_mitre(alert_json: Dict[str, Any]) -> bool:
    mitre_ids = get_nested(alert_json, ["rule", "mitre", "id"], [])
    if isinstance(mitre_ids, list):
        return len(mitre_ids) > 0
    if isinstance(mitre_ids, str):
        return len(mitre_ids.strip()) > 0
    return False

def map_level_to_iris_severity(level) -> int:
    lvl = safe_int(level, 0)
    if lvl >= 13:
        return 5
    if lvl >= 10:
        return 4
    if lvl >= 7:
        return 3
    if lvl >= 4:
        return 2
    return 1

def extract_alert_fields(alert_json: Dict[str, Any]) -> Dict[str, str]:
    data = alert_json.get("data", {})
    fields: Dict[str, str] = {
        "eventid": "",
        "image": "",
        "commandLine": "",
        "parentImage": "",
        "parentCommandLine": "",
        "targetFilename": "",
        "user": "",
        "hashes": "",
        "destinationIp": "",
        "destinationPort": "",
        "message": ""
    }

    if isinstance(data, dict) and "win" in data:
        win = data.get("win", {}) or {}
        ed = win.get("eventdata", {}) or {}
        sysw = win.get("system", {}) or {}

        fields["eventid"] = str(sysw.get("eventID", "") or "")
        fields["image"] = str(ed.get("image") or ed.get("originalFileName") or "")
        fields["commandLine"] = str(ed.get("commandLine") or "")
        fields["parentImage"] = str(ed.get("parentImage") or "")
        fields["parentCommandLine"] = str(ed.get("parentCommandLine") or "")
        fields["targetFilename"] = str(ed.get("targetFilename") or "")
        fields["user"] = str(ed.get("user") or "")
        fields["hashes"] = str(ed.get("hashes") or ed.get("md5") or ed.get("sha256") or "")
        fields["destinationIp"] = str(ed.get("destinationIp") or "")
        fields["destinationPort"] = str(ed.get("destinationPort") or "")
        fields["message"] = str(sysw.get("message") or "")

    elif isinstance(data, dict) and "audit" in data:
        aud = data.get("audit", {}) or {}
        fields["commandLine"] = str(aud.get("command") or aud.get("execve_args") or "")
        fields["image"] = str(aud.get("exe") or aud.get("command") or "")
        fields["user"] = str(aud.get("user") or aud.get("acct") or "")
        fields["targetFilename"] = str(aud.get("file") or aud.get("path") or "")
        fields["eventid"] = "Linux-Audit"

    else:
        if isinstance(data, dict):
            fields["destinationIp"] = str(data.get("dstip") or data.get("dest_ip") or "")
            fields["destinationPort"] = str(data.get("dstport") or data.get("dest_port") or "")
            fields["commandLine"] = str(data.get("command") or "")
            fields["user"] = str(data.get("srcuser") or data.get("user") or "")

    for k in list(fields.keys()):
        v = fields[k]
        fields[k] = "" if v is None else str(v)

    return fields

def matches_any(patterns: List[str], value: Optional[str]) -> bool:
    if not value or not isinstance(value, str):
        return False
    for pat in patterns:
        try:
            if re.search(pat, value, re.IGNORECASE):
                return True
        except Exception:
            continue
    return False

def allowlisted(fields: Dict[str, str]) -> Optional[Tuple[str, str]]:
    if matches_any(ALLOWLIST_CMDLINE_PATTERNS, fields.get("commandLine")):
        return ("allowlist_cmdline", fields.get("commandLine") or "")
    if matches_any(ALLOWLIST_IMAGE_PATTERNS, fields.get("image")):
        return ("allowlist_image", fields.get("image") or "")
    if matches_any(ALLOWLIST_TARGETFILE_PATTERNS, fields.get("targetFilename")):
        return ("allowlist_targetfile", fields.get("targetFilename") or "")
    return None

def build_dedup_hash(rule_id: str, agent_id: str, fields: Dict[str, str]) -> str:
    base_parts = [
        str(rule_id),
        str(agent_id),
        str(fields.get("image", "")),
        str(fields.get("commandLine", "")),
        str(fields.get("targetFilename", "")),
        str(fields.get("destinationIp", "")),
    ]
    base = "|".join(base_parts)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def build_title(rule_desc: str, agent_name: str, rule_id: str, fields: Dict[str, str]) -> str:
    short = rule_desc or "Wazuh Alert"
    artifact = fields.get("targetFilename") or fields.get("commandLine") or fields.get("image") or ""
    if artifact and len(artifact) > 60:
        artifact = artifact[:60] + "..."
    parts = [f"Wazuh: {short}", f"{agent_name}"]
    if artifact:
        parts.append(artifact)
    return " | ".join(parts)

def sanitize_for_plain_text(s: str) -> str:
    if not s or not isinstance(s, str):
        return ""
    s = re.sub(r"(?m)^\s*[\*\#>\-]+\s*", "", s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return s

def build_plain_description(alert_json: Dict[str, Any], fields: Dict[str, str]) -> str:
    rule = alert_json.get("rule", {}) or {}
    agent = alert_json.get("agent", {}) or {}

    rule_id = str(rule.get("id", "") or "")
    level = str(rule.get("level", "") or "")
    rdesc = str(rule.get("description", "") or "")
    agent_name = str(agent.get("name", "") or "")
    agent_ip = str(agent.get("ip", "") or "")
    ts = str(alert_json.get("timestamp", "") or "")

    lines = []
    lines.append("WAZUH ALERT DETAILS")
    if ts:
        lines.append(f"Timestamp: {ts}")
    lines.append(f"Rule ID: {rule_id}")
    lines.append(f"Level: {level}")
    lines.append(f"Description: {rdesc}")
    if agent_name or agent_ip:
        lines.append(f"Agent: {agent_name} ({agent_ip})" if agent_ip else f"Agent: {agent_name}")
    lines.append("")

    lines.append("KEY ARTIFACTS")
    order = [
        ("eventid", "Event ID"),
        ("user", "User"),
        ("image", "Image (Process)"),
        ("commandLine", "Command Line"),
        ("parentImage", "Parent Process Image"),
        ("parentCommandLine", "Parent Command Line"),
        ("targetFilename", "Target Filename"),
        ("destinationIp", "Destination IP"),
        ("destinationPort", "Destination Port"),
        ("hashes", "Hashes"),
    ]
    for k, label in order:
        v = fields.get(k, "") or ""
        if not v:
            continue
        v_clean = sanitize_for_plain_text(v)
        if k in ("commandLine", "parentCommandLine"):
            lines.append(f"{label}:")
            lines.append(v_clean)
        else:
            lines.append(f"{label}: {v_clean}")
    lines.append("")

    def norm_list(x) -> str:
        if isinstance(x, list):
            return ", ".join([str(i) for i in x if str(i).strip()])
        if isinstance(x, str):
            return x.strip()
        return ""

    mitre_ids = norm_list(get_nested(alert_json, ["rule", "mitre", "id"], []))
    tactic = norm_list(get_nested(alert_json, ["rule", "mitre", "tactic"], []))
    technique = norm_list(get_nested(alert_json, ["rule", "mitre", "technique"], []))

    if mitre_ids or tactic or technique:
        lines.append("MITRE ATT&CK MAPPING")
        if mitre_ids:
            lines.append(f"Technique ID: {mitre_ids}")
        if tactic:
            lines.append(f"Tactic: {tactic}")
        if technique:
            lines.append(f"Technique Name: {technique}")
        lines.append("")

    raw_msg = fields.get("message", "") or ""
    if raw_msg:
        lines.append("RAW EVENT MESSAGE")
        lines.append(sanitize_for_plain_text(raw_msg))

    return "\n".join(lines).strip()

def build_tags(rule_id: str, agent_name: str, fields: Dict[str, str], alert_json: Dict[str, Any]) -> str:
    tags = ["wazuh", f"rule-{rule_id}", f"agent-{agent_name}"]

    if fields.get("eventid"):
        tags.append(f"eid-{fields.get('eventid')}")

    mitre_ids = get_nested(alert_json, ["rule", "mitre", "id"], [])
    if isinstance(mitre_ids, list):
        for mid in mitre_ids:
            if str(mid).strip():
                tags.append(f"mitre-{str(mid).strip()}")
    elif isinstance(mitre_ids, str) and mitre_ids.strip():
        tags.append(f"mitre-{mitre_ids.strip()}")

    tf = fields.get("targetFilename") or ""
    if "." in tf:
        ext = tf.lower().split(".")[-1]
        if ext in ["exe", "dll", "ps1", "vbs", "bat", "sh", "py"]:
            tags.append(f"ext-{ext}")

    # async AI tag
    tags.append(TAG_AI_PENDING)

    return ",".join(tags)

def shrink_source_content(obj: Dict[str, Any], max_chars: int) -> Dict[str, Any]:
    """
    Ensure alert_source_content doesn't get huge.
    Keeps structure but truncates full JSON string if needed.
    """
    try:
        s = json.dumps(obj, ensure_ascii=False)
        if len(s) <= max_chars:
            return obj
        # If too large: drop noisy fields if present, then re-check
        slim = dict(obj)
        if "full_log" in slim:
            slim["full_log"] = ""
        if "data" in slim and isinstance(slim["data"], dict):
            # keep data but do not touch unless needed
            pass
        s2 = json.dumps(slim, ensure_ascii=False)
        if len(s2) <= max_chars:
            return slim
        # last resort: store a truncated string
        return {"truncated": True, "payload": s2[:max_chars] + "...(truncated)"}
    except Exception:
        return obj

# ============================================================
# MAIN
# ============================================================

def main():
    if len(sys.argv) < 4:
        log("[FATAL] Missing arguments. Expected: script alert_file api_key hook_url")
        sys.exit(1)

    alert_file = sys.argv[1]
    api_key = sys.argv[2]     # Bearer token
    hook_url = sys.argv[3]    # IRIS endpoint

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert_json = json.load(f)
    except Exception as e:
        log(f"[FATAL] Cannot read alert file: {e}")
        sys.exit(1)

    rule = alert_json.get("rule", {}) or {}
    agent = alert_json.get("agent", {}) or {}
    rule_id = str(rule.get("id", "0"))
    agent_id = str(agent.get("id", "000"))
    agent_name = str(agent.get("name", "unknown"))
    level = safe_int(rule.get("level", 0))

    fields = extract_alert_fields(alert_json)

    # Hard filters
    if agent_name in SUPPRESS_AGENTS:
        sys.exit(0)
    if rule_id in SUPPRESS_RULE_IDS:
        sys.exit(0)

    al = allowlisted(fields)
    if al:
        why, val = al
        log(f"[DROP] Allowlist: {why} matched '{val}' (Rule: {rule_id})")
        sys.exit(0)

    mitre_present = has_mitre(alert_json)
    high_signal = rule_id in HIGH_SIGNAL_RULE_IDS

    should_send = False
    if level >= MIN_WAZUH_LEVEL_TO_FORWARD:
        should_send = True
    elif mitre_present and FORWARD_IF_MITRE_PRESENT:
        should_send = True
    elif high_signal and FORWARD_IF_RULE_IN_HIGH_SIGNAL:
        should_send = True

    if not should_send:
        sys.exit(0)

    # Dedup + burst
    conn = db_init()
    now_ts = int(time.time())

    try:
        if conn:
            burst_dim = fields.get("image") or fields.get("targetFilename") or ""
            burst_key = f"{agent_id}|{rule_id}|{burst_dim}"

            if burst_suppressed(conn, burst_key, now_ts):
                log(f"[DROP] Burst limit hit: {agent_name} Rule {rule_id}")
                sys.exit(0)

            dedup_h = build_dedup_hash(rule_id, agent_id, fields)
            if is_duplicate(conn, dedup_h, now_ts):
                log(f"[DROP] Duplicate: {agent_name} Rule {rule_id}")
                sys.exit(0)
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass

    severity = map_level_to_iris_severity(level)
    title = build_title(str(rule.get("description", "")), agent_name, rule_id, fields)
    plain_desc = build_plain_description(alert_json, fields)
    tags = build_tags(rule_id, agent_name, fields, alert_json)

    safe_source_content = shrink_source_content(alert_json, MAX_SOURCE_CONTENT_CHARS)

    payload = {
        "alert_title": title,
        "alert_description": plain_desc,
        "alert_source": "wazuh",
        "alert_source_ref": f"{agent_name}:{rule_id}:{now_ts}",
        "alert_severity_id": severity,
        "alert_status_id": IRIS_STATUS_ID,
        "alert_customer_id": IRIS_CUSTOMER_ID,
        "alert_source_event_time": str(alert_json.get("timestamp", "")),
        "alert_note": "Via custom-iris integration",
        "alert_tags": tags,
        "alert_source_content": safe_source_content
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(hook_url, json=payload, headers=headers, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
            if resp.status_code in (200, 201):
                log(f"[SENT] Success: Rule {rule_id} -> {agent_name}")
                sys.exit(0)

            body_preview = (resp.text or "")[:800]
            log(f"[FAIL] IRIS {resp.status_code}: {body_preview}")

            if 400 <= resp.status_code < 500:
                sys.exit(1)

        except Exception as e:
            log(f"[ERR] Attempt {attempt}/{MAX_RETRIES}: {e}")

        time.sleep(RETRY_DELAY)

    sys.exit(1)

if __name__ == "__main__":
    main()
