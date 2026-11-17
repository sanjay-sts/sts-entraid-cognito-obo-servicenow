"""OBO broker: Cognito RFC 8693 token exchange (impersonation) with an in-process TTL cache.

Request shape is exactly the one proven in the lab (see CLAUDE.md). The cache is a
performance optimisation only; losing it on restart just means re-exchanging.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx
from fastmcp.exceptions import ToolError

from .settings import Settings

log = logging.getLogger("sn_obo_mcp.obo")

GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
SKEW = 60  # seconds before exp at which a cached token is considered stale
MAX_ENTRIES = 1024


class OboError(ToolError):
    """Token exchange failed; message is safe to show to the caller."""


def jwt_claims(token: str) -> dict[str, Any]:
    """Decode a JWT payload WITHOUT verification (for exp / display only)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


class OboBroker:
    def __init__(self, settings: Settings, http: httpx.AsyncClient | None = None,
                 clock: Callable[[], float] = time.time):
        self._s = settings
        self._http = http or httpx.AsyncClient(timeout=10.0)
        self._clock = clock
        self._cache: dict[tuple[str, str, str], tuple[str, float]] = {}
        self._locks: dict[tuple[str, str, str], asyncio.Lock] = {}

    async def exchange(self, subject_token: str) -> str:
        audience, scope = self._s.obo_audience, self._s.user_scope
        digest = hashlib.sha256(subject_token.encode()).hexdigest()
        key = (digest, audience, scope)
        who = jwt_claims(subject_token).get("username", "?")

        hit = self._get(key)
        if hit:
            log.info("obo cache hit user=%s key=%s", who, digest[:8])
            return hit

        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            hit = self._get(key)  # another task may have filled it
            if hit:
                log.info("obo cache hit user=%s key=%s", who, digest[:8])
                return hit
            token, expires_in = await self._request(subject_token, audience, scope, who)
            now = self._clock()
            exp = jwt_claims(token).get("exp")
            lifetime = min(expires_in, exp - now) if isinstance(exp, (int, float)) else expires_in
            if lifetime - SKEW > 0:
                self._put(key, token, now + lifetime - SKEW)
            log.info("obo exchanged user=%s key=%s lifetime=%ss", who, digest[:8], int(lifetime))
            return token

    def _get(self, key) -> str | None:
        entry = self._cache.get(key)
        if entry and entry[1] > self._clock():
            return entry[0]
        if entry:
            self._cache.pop(key, None)
        return None

    def _put(self, key, token: str, valid_until: float) -> None:
        if len(self._cache) >= MAX_ENTRIES:
            now = self._clock()
            for k in [k for k, (_, v) in self._cache.items() if v <= now]:
                self._cache.pop(k, None)
                self._locks.pop(k, None)
            while len(self._cache) >= MAX_ENTRIES:
                oldest = min(self._cache, key=lambda k: self._cache[k][1])
                self._cache.pop(oldest, None)
                self._locks.pop(oldest, None)
        self._cache[key] = (token, valid_until)

    async def _request(self, subject_token: str, audience: str, scope: str, who: str) -> tuple[str, float]:
        try:
            r = await self._http.post(
                f"{self._s.cog_url}/oauth2/token",
                auth=(self._s.obo_client_id, self._s.obo_client_secret),
                data={
                    "grant_type": GRANT,
                    "subject_token": subject_token,
                    "subject_token_type": ACCESS_TOKEN_TYPE,
                    "audience": audience,
                    "scope": scope,
                },
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as e:
            log.warning("obo exchange transport error user=%s: %s", who, type(e).__name__)
            raise OboError("Token exchange with Cognito failed (network). Please retry.") from None

        try:
            body = r.json()
        except ValueError:
            body = {}

        if r.status_code == 200 and body.get("access_token"):
            return body["access_token"], float(body.get("expires_in", 3600))

        err = body.get("error", "")
        log.warning("obo exchange failed user=%s status=%s error=%s desc=%s",
                    who, r.status_code, err, body.get("error_description", ""))
        if err == "invalid_grant":
            raise OboError(
                "Your session cannot be exchanged for a ServiceNow token (expired, or the login "
                f"did not include {scope}). Please re-authenticate."
            )
        if err in ("invalid_client", "unauthorized_client", "invalid_scope", "invalid_target"):
            raise OboError("Server token-exchange configuration error; contact the administrator.")
        if r.status_code >= 500 or r.status_code == 429:
            raise OboError("Cognito token exchange is temporarily unavailable. Please retry.")
        raise OboError(f"Token exchange failed ({r.status_code} {err or 'error'}).")
