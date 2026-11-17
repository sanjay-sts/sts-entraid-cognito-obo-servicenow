"""sn-obo-mcp: stateless FastMCP server, Cognito OBO to ServiceNow.

Run:  uv run python server.py
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import httpx
from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from sn_obo_mcp.auth import build_auth
from sn_obo_mcp.obo import OboBroker
from sn_obo_mcp.oauth_routes import register_routes
from sn_obo_mcp.servicenow import ServiceNowClient
from sn_obo_mcp.settings import Settings
from sn_obo_mcp.tools import register_tools


def create_mcp(settings: Settings, cognito_client_factory: Callable[[], Any] | None = None,
               http: httpx.AsyncClient | None = None) -> FastMCP:
    mcp = FastMCP("servicenow-obo", auth=build_auth(settings))
    http = http or httpx.AsyncClient(timeout=20.0)
    register_routes(mcp, settings, cognito_client_factory, http)
    register_tools(mcp, OboBroker(settings, http), ServiceNowClient(settings.sn_url, http))
    return mcp


def create_app(settings: Settings, cognito_client_factory: Callable[[], Any] | None = None,
               http: httpx.AsyncClient | None = None):
    # Browser-based MCP clients (MCP Inspector) do discovery, DCR and /mcp calls cross-origin.
    # Bearer tokens only (no cookies), so no credentials; origins limited to loopback for the lab.
    cors = Middleware(
        CORSMiddleware,
        allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["WWW-Authenticate", "Mcp-Session-Id", "Mcp-Protocol-Version"],
        max_age=600,
    )
    return create_mcp(settings, cognito_client_factory, http).http_app(stateless_http=True, middleware=[cors])


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.from_env()
    logging.getLogger("sn_obo_mcp").info(
        "Starting: base_url=%s issuer=%s m2m_enabled=%s", settings.base_url, settings.issuer, settings.m2m_enabled
    )
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
