"""Thin async ServiceNow REST client (Bearer = OBO token) with readable error mapping."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from fastmcp.exceptions import ToolError

log = logging.getLogger("sn_obo_mcp.servicenow")

MAX_LIMIT = 50


class ServiceNowError(ToolError):
    """ServiceNow call failed; message is safe to show to the caller."""


def clamp_limit(limit: int) -> int:
    return max(1, min(int(limit), MAX_LIMIT))


def safe_query_text(text: str) -> str:
    """Neutralise encoded-query operators so user text can't add conditions."""
    return " ".join(text.replace("^", " ").split())


def _sn_message(r: httpx.Response) -> str:
    try:
        err = r.json().get("error") or {}
        parts = [err.get("message"), err.get("detail")]
        return " - ".join(p for p in parts if p) or r.reason_phrase
    except Exception:
        return r.reason_phrase


class ServiceNowClient:
    def __init__(self, base_url: str, http: httpx.AsyncClient | None = None):
        self._base = base_url.rstrip("/")
        self._http = http or httpx.AsyncClient(timeout=20.0)

    async def request(self, method: str, path: str, token: str, *,
                      params: dict[str, Any] | None = None, json: dict | None = None) -> Any:
        try:
            r = await self._http.request(
                method, f"{self._base}{path}", params=params, json=json,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            )
        except httpx.HTTPError as e:
            log.warning("ServiceNow transport error %s %s: %s", method, path, type(e).__name__)
            raise ServiceNowError("Could not reach ServiceNow. Please retry.") from None

        if r.status_code in (200, 201):
            return r.json().get("result")
        if r.status_code == 204:
            return None
        msg = _sn_message(r)
        log.info("ServiceNow %s %s -> %s %s", method, path, r.status_code, msg)
        if r.status_code == 401:
            raise ServiceNowError("ServiceNow rejected the token (401). Please re-authenticate.")
        if r.status_code == 403:
            raise ServiceNowError(f"ServiceNow ACL denied: {msg}")
        if r.status_code == 404:
            raise ServiceNowError("Not found or not visible to you.")
        if r.status_code == 429 or r.status_code >= 500:
            raise ServiceNowError(f"ServiceNow is temporarily unavailable ({r.status_code}). Please retry.")
        raise ServiceNowError(f"ServiceNow request failed ({r.status_code}): {msg}")

    async def table_get(self, token: str, table: str, *, query: str = "", fields: list[str] | None = None,
                        limit: int = 20, display_value: bool = True) -> list[dict]:
        params: dict[str, Any] = {"sysparm_limit": clamp_limit(limit),
                                  "sysparm_display_value": str(display_value).lower(),
                                  "sysparm_exclude_reference_link": "true"}
        if query:
            params["sysparm_query"] = query
        if fields:
            params["sysparm_fields"] = ",".join(fields)
        return await self.request("GET", f"/api/now/table/{table}", token, params=params) or []

    async def table_create(self, token: str, table: str, body: dict, fields: list[str] | None = None) -> dict:
        params = {"sysparm_display_value": "true", "sysparm_exclude_reference_link": "true"}
        if fields:
            params["sysparm_fields"] = ",".join(fields)
        return await self.request("POST", f"/api/now/table/{table}", token, params=params, json=body)

    async def table_patch(self, token: str, table: str, sys_id: str, body: dict,
                          fields: list[str] | None = None) -> dict:
        params = {"sysparm_display_value": "true", "sysparm_exclude_reference_link": "true"}
        if fields:
            params["sysparm_fields"] = ",".join(fields)
        return await self.request("PATCH", f"/api/now/table/{table}/{sys_id}", token, params=params, json=body)
