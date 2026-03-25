#!/usr/bin/env python3
"""
View — Wazuh MCP Server + SOC Dashboard + Ollama AI
A completely original implementation by Nitesh.
"""

import json, logging, os
from pathlib import Path
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Mount, Route

from wazuh_api import WazuhConfig, WazuhSession, WazuhError

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
log = logging.getLogger("sentinel")

# ── Config ────────────────────────────────────────────────
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi4-mini")
STATIC = Path(__file__).parent / "static"

_session: Optional[WazuhSession] = None

def wazuh() -> WazuhSession:
    global _session
    if _session is None:
        _session = WazuhSession(WazuhConfig(
            url=os.getenv("WAZUH_URL", ""),
            user=os.getenv("WAZUH_USER", ""),
            password=os.getenv("WAZUH_PASS", ""),
            verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "true").lower() not in {"0", "false", "no"},
        ))
    return _session

def truncate(text: str, n: int = 30000) -> str:
    return text if len(text) <= n else text[:n] + f"\n[…truncated {len(text)-n} chars]"

# ── MCP Tools ─────────────────────────────────────────────
mcp = FastMCP(name="View", version="1.0.0")

@mcp.tool()
async def refresh_auth() -> str:
    """Force a fresh JWT from the Wazuh Manager."""
    s = wazuh(); s._jwt = None
    await s._ensure_token()
    return "Token refreshed ✓"

@mcp.tool()
async def list_agents(status: str = None, limit: int = 500) -> str:
    """List agents, optionally filtered by status (active/disconnected/pending)."""
    data = await wazuh().agents(status=status, limit=limit)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def get_agent(agent_id: str) -> str:
    """Get detailed info for a specific agent by ID."""
    data = await wazuh().agent(agent_id)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def agent_vulnerabilities(agent_id: str, limit: int = 100) -> str:
    """List known vulnerabilities for an agent."""
    data = await wazuh().vulnerabilities(agent_id, limit=limit)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def agent_ports(agent_id: str) -> str:
    """List open network ports for an agent."""
    data = await wazuh().agent_ports(agent_id)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def agent_processes(agent_id: str) -> str:
    """List running processes for an agent."""
    data = await wazuh().agent_processes(agent_id)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def agent_packages(agent_id: str) -> str:
    """List installed packages for an agent."""
    data = await wazuh().agent_packages(agent_id)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def agent_sca(agent_id: str) -> str:
    """Get Security Configuration Assessment results for an agent."""
    data = await wazuh().sca(agent_id)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def sca_policy_checks(agent_id: str, policy_id: str) -> str:
    """Get detailed checks for a specific SCA policy on an agent."""
    data = await wazuh().sca_checks(agent_id, policy_id)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def list_rules(limit: int = 100) -> str:
    """List Wazuh detection rules."""
    data = await wazuh().rules(limit=limit)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def list_decoders(limit: int = 100) -> str:
    """List Wazuh log decoders."""
    data = await wazuh().decoders(limit=limit)
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def cluster_status() -> str:
    """Check Wazuh cluster health."""
    data = await wazuh().cluster_health()
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def manager_info() -> str:
    """Get Wazuh Manager version and system info."""
    data = await wazuh().manager_info()
    return truncate(json.dumps(data, indent=2))

@mcp.tool()
async def manager_logs(limit: int = 50) -> str:
    """Retrieve recent Wazuh Manager log entries."""
    data = await wazuh().manager_logs(limit=limit)
    return truncate(json.dumps(data, indent=2))

# ── Dashboard Routes ──────────────────────────────────────

async def page_dashboard(req):
    f = STATIC / "index.html"
    return HTMLResponse(f.read_text("utf-8") if f.exists() else "<h1>Missing UI</h1>")

async def api_health(req):
    w = False
    try: w = await wazuh().ping()
    except: pass
    o = False
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{OLLAMA_URL}/api/version")
            o = r.status_code == 200
    except: pass
    return JSONResponse({
        "wazuh": w, "ollama": o,
        "wazuh_url": os.getenv("WAZUH_URL",""),
        "ollama_model": OLLAMA_MODEL, "ollama_url": OLLAMA_URL,
    })

async def api_agents(req):
    try:
        data = await wazuh().agents(
            status=req.query_params.get("status"),
            limit=int(req.query_params.get("limit", 500)),
        )
        return JSONResponse(data)
    except Exception as e:
        log.warning("agents: %s", e)
        return JSONResponse({"data":{"affected_items":[],"total_affected_items":0},"warning":str(e)})

async def api_agent_detail(req):
    try:
        data = await wazuh().agent(req.path_params["id"])
        return JSONResponse(data)
    except Exception as e:
        return JSONResponse({"data":{"affected_items":[]},"warning":str(e)})

async def api_vulns(req):
    try:
        data = await wazuh().vulnerabilities(req.path_params["id"])
        return JSONResponse(data)
    except Exception as e:
        return JSONResponse({"data":{"affected_items":[]},"warning":str(e)})

async def api_rules(req):
    try:
        data = await wazuh().rules(limit=int(req.query_params.get("limit",100)))
        return JSONResponse(data)
    except Exception as e:
        return JSONResponse({"data":{"affected_items":[]},"warning":str(e)})
async def _smart_fetch(user_msg: str) -> str:
    """Intelligently fetch Wazuh data based on what the user is asking about."""
    import asyncio, re
    s = wazuh()
    msg = user_msg.lower()
    ctx = []

    async def _safe(label, coro, timeout=8):
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            return f"{label}: Wazuh Manager unreachable (timeout)"
        except Exception as e:
            return f"{label}: Error — {e}"

    # Always fetch agent summary
    async def _agents():
        data = await s.agents(limit=50)
        items = data.get("data", {}).get("affected_items", [])
        if not items:
            return "AGENTS: No agents registered"
        active = sum(1 for a in items if a.get("status") == "active")
        disc = sum(1 for a in items if a.get("status") == "disconnected")
        lines = [f"  [{a.get('id')}] {a.get('name')} | {a.get('ip')} | {a.get('status')} | "
                 f"OS:{a.get('os',{}).get('name','')} | Last:{a.get('lastKeepAlive','')}"
                 for a in items[:30]]
        return f"AGENTS SUMMARY: {len(items)} total, {active} active, {disc} disconnected\n" + "\n".join(lines)

    ctx.append(await _safe("AGENTS", _agents()))

    # Always fetch latest logs with pattern analysis
    async def _logs():
        data = await s.manager_logs(limit=50)
        items = data.get("data", {}).get("affected_items", [])
        if not items:
            return "MANAGER LOGS: No entries"
        tag_counts = {}
        error_lines = []
        warning_lines = []
        for l in items:
            tag = l.get("tag", "unknown")
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
            level = l.get("level", "").lower()
            desc = l.get("description", "")
            ts = l.get("timestamp", "")
            line = f"  [{ts}] [{tag}] {desc}"
            if level in ("error", "critical"):
                error_lines.append(line)
            elif level == "warning":
                warning_lines.append(line)
        parts = [f"MANAGER LOGS ANALYSIS ({len(items)} entries scanned):"]
        parts.append(f"  Sources: {', '.join(f'{t}({c})' for t,c in sorted(tag_counts.items(), key=lambda x:-x[1])[:10])}")
        if error_lines:
            parts.append(f"\n  ERRORS ({len(error_lines)}):")
            parts.extend(error_lines[:15])
        if warning_lines:
            parts.append(f"\n  WARNINGS ({len(warning_lines)}):")
            parts.extend(warning_lines[:10])
        ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        ip_counts = {}
        for l in items:
            for ip in ip_pattern.findall(l.get("description", "")):
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
        suspicious = {ip: c for ip, c in ip_counts.items() if c >= 3}
        if suspicious:
            parts.append(f"\n  REPEATED IPs (potential scanning/brute force):")
            for ip, c in sorted(suspicious.items(), key=lambda x:-x[1]):
                parts.append(f"    {ip} appeared {c} times")
        parts.append(f"\n  LATEST 10 RAW ENTRIES:")
        for l in items[:10]:
            parts.append(f"  [{l.get('timestamp','')}] [{l.get('tag','')}] [{l.get('level','')}] {l.get('description','')}")
        return "\n".join(parts)

    ctx.append(await _safe("LOGS", _logs()))

    # Manager info
    async def _info():
        data = await s.manager_info()
        mi = data.get("data", {}).get("affected_items", [{}])[0]
        return f"MANAGER: {mi.get('name','')} v{mi.get('version','')} ({mi.get('type','')})"
    ctx.append(await _safe("INFO", _info()))

    # If user asks about vulnerabilities
    if any(kw in msg for kw in ["vuln", "cve", "patch", "exploit"]):
        async def _vulns():
            agents = await s.agents(limit=5)
            items = agents.get("data", {}).get("affected_items", [])
            all_v = []
            for a in items[:3]:
                try:
                    vd = await s.vulnerabilities(a["id"], limit=20)
                    for v in vd.get("data", {}).get("affected_items", []):
                        all_v.append(f"  Agent {a['name']}({a['id']}): {v.get('cve','')} severity={v.get('severity','')} {v.get('name','')}")
                except: pass
            return f"VULNERABILITIES ({len(all_v)}):\n" + "\n".join(all_v[:30]) if all_v else "VULNERABILITIES: None found"
        ctx.append(await _safe("VULNS", _vulns(), timeout=15))

    # If user asks about rules
    if any(kw in msg for kw in ["rule", "detection", "signature"]):
        async def _rules():
            data = await s.rules(limit=30)
            items = data.get("data", {}).get("affected_items", [])
            lines = [f"  [{r.get('id')}] level={r.get('level')} {r.get('description','')}" for r in items[:30]]
            return f"RULES ({len(items)}):\n" + "\n".join(lines)
        ctx.append(await _safe("RULES", _rules()))

    return "\n\n".join(ctx)


async def api_chat(req):
    try:
        body = await req.json()
        msgs = body.get("messages", [])
        latest_msg = ""
        for m in reversed(msgs):
            if m.get("role") == "user":
                latest_msg = m.get("content", "")
                break
        wazuh_context = await _smart_fetch(latest_msg)
        sys_prompt = {
            "role": "system",
            "content": (
                "You are View AI, the Lead Security Analyst. You are integrated into a live Wazuh SIEM.\n"
                "CRITICAL RULES:\n"
                "1. ONLY discuss data shown below. NEVER invent or hallucinate any alerts, IPs, events, or logs.\n"
                "2. If data says 'unreachable' or 'Error', tell the user the Wazuh Manager connection failed.\n"
                "3. When showing logs, quote the EXACT timestamps and messages from the data.\n"
                "4. Highlight patterns: repeated IPs, error spikes, unauthorized agents, suspicious activity.\n"
                "5. Give actionable recommendations based on REAL findings only.\n"
                "6. Be concise. Use bullet points. Cite specific log entries.\n\n"
                f"=== LIVE WAZUH DATA (fetched just now) ===\n{wazuh_context}\n=== END ==="
            ),
        }
        async with httpx.AsyncClient(timeout=300) as c:
            r = await c.post(
                f"{OLLAMA_URL}/api/chat",
                json={"model": OLLAMA_MODEL, "messages": [sys_prompt]+msgs, "stream": False},
            )
            r.raise_for_status()
            return JSONResponse(r.json())
    except httpx.ConnectError:
        return JSONResponse({"error":"Ollama unreachable. Run: ollama serve"}, status_code=503)
    except Exception as e:
        import traceback; traceback.print_exc()
        return JSONResponse({"error":str(e)}, status_code=500)

async def api_tools(req):
    tools = [
        {"name":"refresh_auth","desc":"Force JWT token refresh","icon":"🔑","cat":"auth"},
        {"name":"list_agents","desc":"List all Wazuh agents","icon":"🖥️","cat":"agents"},
        {"name":"get_agent","desc":"Get agent details by ID","icon":"🔍","cat":"agents"},
        {"name":"agent_vulnerabilities","desc":"CVE scan results per agent","icon":"🛡️","cat":"vuln"},
        {"name":"agent_ports","desc":"Open network ports","icon":"🌐","cat":"recon"},
        {"name":"agent_processes","desc":"Running processes","icon":"⚙️","cat":"recon"},
        {"name":"agent_packages","desc":"Installed packages","icon":"📦","cat":"recon"},
        {"name":"agent_sca","desc":"Security compliance assessment","icon":"✅","cat":"compliance"},
        {"name":"sca_policy_checks","desc":"Detailed SCA policy checks","icon":"📋","cat":"compliance"},
        {"name":"list_rules","desc":"Detection rules","icon":"📜","cat":"rules"},
        {"name":"list_decoders","desc":"Log decoders","icon":"🔧","cat":"rules"},
        {"name":"cluster_status","desc":"Cluster health check","icon":"💚","cat":"cluster"},
        {"name":"manager_info","desc":"Manager version & info","icon":"ℹ️","cat":"system"},
        {"name":"manager_logs","desc":"Recent manager logs","icon":"📰","cat":"system"},
    ]
    return JSONResponse({"tools":tools,"count":len(tools)})

async def api_run_tool(req):
    """Universal tool runner — executes any tool by name with params."""
    try:
        body = await req.json()
        name = body.get("tool", "")
        params = body.get("params", {})
        s = wazuh()
        handlers = {
            "refresh_auth": lambda: _run_auth(s),
            "list_agents": lambda: s.agents(**params),
            "get_agent": lambda: s.agent(params.get("agent_id","")),
            "agent_vulnerabilities": lambda: s.vulnerabilities(params.get("agent_id",""), limit=params.get("limit",100)),
            "agent_ports": lambda: s.agent_ports(params.get("agent_id","")),
            "agent_processes": lambda: s.agent_processes(params.get("agent_id","")),
            "agent_packages": lambda: s.agent_packages(params.get("agent_id","")),
            "agent_sca": lambda: s.sca(params.get("agent_id","")),
            "sca_policy_checks": lambda: s.sca_checks(params.get("agent_id",""), params.get("policy_id","")),
            "list_rules": lambda: s.rules(limit=params.get("limit",100)),
            "list_decoders": lambda: s.decoders(limit=params.get("limit",100)),
            "cluster_status": lambda: s.cluster_health(),
            "manager_info": lambda: s.manager_info(),
            "manager_logs": lambda: s.manager_logs(limit=params.get("limit",50)),
        }
        if name not in handlers:
            return JSONResponse({"error": f"Unknown tool: {name}"}, status_code=400)
        result = await handlers[name]()
        return JSONResponse({"tool": name, "result": result})
    except Exception as e:
        log.warning("run-tool %s: %s", body.get("tool","?"), e)
        return JSONResponse({"tool": body.get("tool",""), "error": str(e)})

async def _run_auth(s):
    s._jwt = None
    await s._ensure_token()
    return {"status": "Token refreshed successfully ✓"}

# ── App Assembly ──────────────────────────────────────────

app = Starlette(
    routes=[
        Route("/", page_dashboard),
        Route("/api/health", api_health),
        Route("/api/agents", api_agents),
        Route("/api/agents/{id}", api_agent_detail),
        Route("/api/agents/{id}/vulns", api_vulns),
        Route("/api/rules", api_rules),
        Route("/api/chat", api_chat, methods=["POST"]),
        Route("/api/tools", api_tools),
        Route("/api/run-tool", api_run_tool, methods=["POST"]),
        Mount("/mcp", app=mcp.http_app()),
    ],
    middleware=[
        Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]),
    ],
)

if __name__ == "__main__":
    import uvicorn
    for v in ("WAZUH_URL","WAZUH_USER","WAZUH_PASS"):
        if not os.getenv(v):
            print(f"✗ Missing env var: {v}"); exit(1)
    host = os.getenv("HOST","0.0.0.0")
    port = int(os.getenv("PORT","8010"))
    print("━"*52)
    print("  👁️  VIEW — Wazuh MCP + SOC Dashboard + AI")
    print("━"*52)
    print(f"  📡 Wazuh   : {os.getenv('WAZUH_URL')}")
    print(f"  🤖 AI      : {OLLAMA_MODEL}")
    print(f"  🌐 Dashboard: http://127.0.0.1:{port}")
    print(f"  🔌 MCP     : http://127.0.0.1:{port}/mcp")
    print("━"*52)
    uvicorn.run(app, host=host, port=port, log_level=os.getenv("LOG_LEVEL","info"))
