"""Offline test fixtures: fake Cognito keys/JWKS, stubbed boto3, no network allowed."""

from __future__ import annotations

import base64
import json
import socket
import sys
from pathlib import Path

import boto3
import httpx
import pytest
from botocore.stub import Stubber
from cryptography.hazmat.primitives import serialization
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server import create_app  # noqa: E402
from sn_obo_mcp.settings import Settings  # noqa: E402

@pytest.fixture
def anyio_backend():
    return "asyncio"


REGION = "us-east-1"
POOL = "us-east-1_TESTPOOL"
ISS = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL}"
BASE = "http://localhost:8000"
KID = "test-kid"
M2M_ID = "m2mclient1"
MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def guard(*a, **k):
        raise RuntimeError("Network access attempted in offline test")

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "create_connection", guard)


def _b64u_int(n: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def _jwks_for(kp: RSAKeyPair) -> dict:
    pub = serialization.load_pem_public_key(kp.public_key.encode()).public_numbers()
    return {"keys": [{"kty": "RSA", "kid": KID, "alg": "RS256", "use": "sig", "n": _b64u_int(pub.n), "e": _b64u_int(pub.e)}]}


@pytest.fixture(scope="session")
def keypair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture(scope="session")
def other_keypair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture(autouse=True)
def _fake_jwks(monkeypatch, keypair):
    jwks = _jwks_for(keypair)

    async def fetch(self):
        return jwks

    monkeypatch.setattr(JWTVerifier, "_fetch_jwks", fetch)


@pytest.fixture
def mint(keypair):
    """Mint a Cognito-shaped access token. kind='user' or 'm2m'."""

    def _mint(kind: str = "user", *, key: RSAKeyPair | None = None, issuer: str = ISS,
              scopes: list[str] | None = None, expires_in: int = 3600, **claims) -> str:
        if kind == "user":
            base = {"username": "EntraID_adelev", "client_id": "dcrclient1", "token_use": "access"}
            default_scopes = ["openid", "email", "profile", "servicenow-api/access"]
            sub = "user-sub-1"
        else:
            base = {"client_id": M2M_ID, "token_use": "access"}
            default_scopes = ["mcp-m2m/invoke"]
            sub = claims.get("client_id", M2M_ID)
        base.update(claims)
        return (key or keypair).create_token(
            subject=sub, issuer=issuer, scopes=default_scopes if scopes is None else scopes,
            expires_in_seconds=expires_in, additional_claims=base, kid=KID,
        )

    return _mint


def make_settings(**overrides) -> Settings:
    values = dict(
        aws_region=REGION, pool_id=POOL,
        cog_url="https://test-domain.auth.us-east-1.amazoncognito.com",
        sn_url="https://sn.example.com", obo_client_id="oboclient", obo_client_secret="obosecret",
        base_url=BASE, m2m_client_ids=(M2M_ID,),
    )
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def cognito_stub():
    client = boto3.client("cognito-idp", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="x")
    with Stubber(client) as stub:
        yield client, stub
        stub.assert_no_pending_responses()


@pytest.fixture
def make_client(cognito_stub):
    """Factory: build an app for given settings and return an httpx client (async ctx manager)."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _make(s: Settings):
        app = create_app(s, cognito_client_factory=lambda: cognito_stub[0])
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as c:
                yield c

    return _make


@pytest.fixture
async def client(make_client, settings):
    async with make_client(settings) as c:
        yield c


async def call_tool(client: httpx.AsyncClient, name: str, args: dict | None = None, token: str | None = None):
    """POST a tools/call; returns (http_status, jsonrpc result or None)."""
    headers = dict(MCP_HEADERS)
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}
    r = await client.post("/mcp", json=body, headers=headers)
    if r.status_code != 200:
        return r.status_code, None
    text = r.text
    if text.lstrip().startswith("event:") or "data:" in text:
        data = next(line[5:].strip() for line in text.splitlines() if line.startswith("data:"))
    else:
        data = text
    return 200, json.loads(data)["result"]
