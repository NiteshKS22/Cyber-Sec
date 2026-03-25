"""
wazuh_api.py — Async Wazuh Manager REST client.
Handles JWT lifecycle, retries, and provides typed helpers
for every major Wazuh API resource.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("sentinel.wazuh")


class WazuhError(Exception):
    """Raised when a Wazuh API call fails."""

    def __init__(self, msg: str, status: int = 0):
        super().__init__(msg)
        self.status = status


@dataclass
class WazuhConfig:
    url: str
    user: str
    password: str
    verify_ssl: bool = False
    timeout: int = 30


class WazuhSession:
    """
    Lightweight async wrapper around the Wazuh Manager REST API.
    Manages JWT token acquisition and automatic refresh.
    """

    TOKEN_LIFETIME = 900  # 15 min default

    def __init__(self, cfg: WazuhConfig):
        self._cfg = cfg
        self._jwt: Optional[str] = None
        self._jwt_exp: float = 0.0
        self._http = httpx.AsyncClient(
            base_url=cfg.url,
            verify=cfg.verify_ssl,
            timeout=cfg.timeout,
            http2=True,
        )

    # ── auth ──────────────────────────────────────────────

    async def _ensure_token(self) -> None:
        if self._jwt and time.time() < self._jwt_exp - 60:
            return
        log.debug("Acquiring new JWT from %s", self._cfg.url)
        resp = await self._http.post(
            "/security/user/authenticate",
            auth=(self._cfg.user, self._cfg.password),
        )
        if resp.status_code != 200:
            raise WazuhError(f"Auth failed ({resp.status_code}): {resp.text}", resp.status_code)
        self._jwt = resp.json()["data"]["token"]
        self._jwt_exp = time.time() + self.TOKEN_LIFETIME

    async def ping(self) -> bool:
        """Return True if the manager is reachable and credentials work."""
        try:
            await self._ensure_token()
            return True
        except Exception:
            return False

    # ── generic request ───────────────────────────────────

    async def call(self, method: str, path: str, **kw) -> Dict[str, Any]:
        await self._ensure_token()
        kw.setdefault("headers", {})["Authorization"] = f"Bearer {self._jwt}"
        resp = await self._http.request(method, path, **kw)
        if resp.status_code >= 400:
            raise WazuhError(f"{method} {path} → {resp.status_code}", resp.status_code)
        return resp.json()

    # ── resource helpers ──────────────────────────────────

    async def agents(self, *, status: str = None, limit: int = 500, offset: int = 0) -> Dict:
        p: Dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            p["status"] = status
        return await self.call("GET", "/agents", params=p)

    async def agent(self, agent_id: str) -> Dict:
        return await self.call("GET", f"/agents", params={"agents_list": agent_id})

    async def agent_os(self, agent_id: str) -> Dict:
        return await self.call("GET", f"/syscollector/{agent_id}/os")

    async def agent_ports(self, agent_id: str) -> Dict:
        return await self.call("GET", f"/syscollector/{agent_id}/ports", params={"limit": 500})

    async def agent_processes(self, agent_id: str) -> Dict:
        return await self.call("GET", f"/syscollector/{agent_id}/processes", params={"limit": 500})

    async def agent_packages(self, agent_id: str) -> Dict:
        return await self.call("GET", f"/syscollector/{agent_id}/packages", params={"limit": 500})

    async def agent_netiface(self, agent_id: str) -> Dict:
        return await self.call("GET", f"/syscollector/{agent_id}/netiface")

    async def vulnerabilities(self, agent_id: str, *, limit: int = 100) -> Dict:
        return await self.call("GET", f"/vulnerability/{agent_id}", params={"limit": limit})

    async def sca(self, agent_id: str) -> Dict:
        return await self.call("GET", f"/sca/{agent_id}")

    async def sca_checks(self, agent_id: str, policy_id: str) -> Dict:
        return await self.call("GET", f"/sca/{agent_id}/checks/{policy_id}", params={"limit": 500})

    async def rules(self, *, limit: int = 100, offset: int = 0) -> Dict:
        return await self.call("GET", "/rules", params={"limit": limit, "offset": offset})

    async def rule_files(self) -> Dict:
        return await self.call("GET", "/rules/files")

    async def decoders(self, *, limit: int = 100) -> Dict:
        return await self.call("GET", "/decoders", params={"limit": limit})

    async def cluster_health(self) -> Dict:
        return await self.call("GET", "/cluster/healthcheck")

    async def cluster_nodes(self) -> Dict:
        return await self.call("GET", "/cluster/nodes")

    async def manager_info(self) -> Dict:
        return await self.call("GET", "/manager/info")

    async def manager_stats(self) -> Dict:
        return await self.call("GET", "/manager/stats")

    async def manager_logs(self, *, limit: int = 50) -> Dict:
        return await self.call("GET", "/manager/logs", params={"limit": limit})

    async def close(self) -> None:
        await self._http.aclose()
