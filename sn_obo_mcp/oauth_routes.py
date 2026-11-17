"""Unauthenticated HTTP routes: RFC 8414 metadata facade, RFC 7591 DCR shim, /health,
and thin stateless /authorize + /token pass-throughs to Cognito.

The facade advertises *our* base URL as issuer (so MCP clients accept it). Tokens remain
Cognito-issued; nothing is stored here.

Why /authorize and /token exist: MCP clients send RFC 8707 `resource=<server>/mcp`.
Cognito honours resource binding and then demands that every custom scope belongs to a
resource server whose identifier equals that URI -> `invalid_target`. Our scope belongs to
`servicenow-api` (needed for the OBO exchange), so we drop `resource` and forward the rest.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlencode, urlsplit

import anyio
import httpx
from botocore.exceptions import ClientError
from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from .settings import Settings

log = logging.getLogger("sn_obo_mcp.dcr")

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1"}
_NAME_BAD_CHARS = re.compile(r"[^\w\s+=,.@-]")


def make_cognito_client(settings: Settings):
    import boto3

    session = boto3.session.Session(profile_name=settings.aws_profile, region_name=settings.aws_region)
    return session.client("cognito-idp")


def as_metadata(settings: Settings) -> dict[str, Any]:
    return {
        "issuer": settings.base_url,
        "authorization_endpoint": f"{settings.base_url}/authorize",
        "token_endpoint": f"{settings.base_url}/token",
        "revocation_endpoint": f"{settings.cog_url}/oauth2/revoke",
        "registration_endpoint": f"{settings.base_url}/register",
        "jwks_uri": settings.jwks_uri,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "revocation_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": settings.login_scopes,
    }


def redirect_allowed(uri: str, allowlist: tuple[str, ...]) -> bool:
    if uri in allowlist:
        return True
    try:
        parts = urlsplit(uri)
        _ = parts.port  # raises on malformed port
    except ValueError:
        return False
    return (
        parts.scheme == "http"
        and parts.hostname in _LOOPBACK_HOSTS
        and not parts.username
        and not parts.password
        and not parts.fragment
    )


def _error(status: int, error: str, description: str) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": description}, status_code=status)


def register_routes(
    mcp: FastMCP,
    settings: Settings,
    cognito_client_factory: Callable[[], Any] | None = None,
    http: httpx.AsyncClient | None = None,
) -> None:
    metadata = as_metadata(settings)
    http = http or httpx.AsyncClient(timeout=10.0)
    factory = cognito_client_factory or (lambda: make_cognito_client(settings))
    _client: list[Any] = []

    def cognito():
        if not _client:
            _client.append(factory())
        return _client[0]

    async def _metadata(_: Request) -> JSONResponse:
        return JSONResponse(metadata, headers={"Cache-Control": "public, max-age=3600"})

    mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])(_metadata)
    mcp.custom_route("/.well-known/openid-configuration", methods=["GET"])(_metadata)

    @mcp.custom_route("/authorize", methods=["GET"])
    async def authorize(request: Request) -> Response:
        params = [(k, v) for k, v in request.query_params.multi_items() if k != "resource"]
        if not any(k == "identity_provider" for k, _ in params):
            params.append(("identity_provider", settings.idp_name))  # skip the Cognito IdP picker
        if settings.authorize_prompt and not any(k == "prompt" for k, _ in params):
            params.append(("prompt", settings.authorize_prompt))  # force account choice / re-login
        return RedirectResponse(f"{settings.cog_url}/oauth2/authorize?{urlencode(params)}", status_code=302)

    @mcp.custom_route("/token", methods=["POST"])
    async def token(request: Request) -> Response:
        form = await request.form()
        data = [(k, v) for k, v in form.multi_items() if k != "resource" and isinstance(v, str)]
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        if auth := request.headers.get("authorization"):
            headers["Authorization"] = auth  # confidential clients using client_secret_basic
        try:
            r = await http.post(f"{settings.cog_url}/oauth2/token", content=urlencode(data), headers=headers)
        except httpx.HTTPError as e:
            log.warning("token pass-through transport error: %s", type(e).__name__)
            return _error(502, "temporarily_unavailable", "Could not reach the authorization server")
        return Response(r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type", "application/json"),
                        headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "m2m_enabled": settings.m2m_enabled})

    @mcp.custom_route("/register", methods=["POST"])
    async def register(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return _error(400, "invalid_client_metadata", "Body must be JSON")
        if not isinstance(body, dict):
            return _error(400, "invalid_client_metadata", "Body must be a JSON object")

        redirect_uris = body.get("redirect_uris")
        if (
            not isinstance(redirect_uris, list)
            or not redirect_uris
            or not all(isinstance(u, str) and u for u in redirect_uris)
        ):
            return _error(400, "invalid_redirect_uri", "redirect_uris must be a non-empty list")
        bad = [u for u in redirect_uris if not redirect_allowed(u, settings.dcr_redirect_allowlist)]
        if bad:
            return _error(
                400, "invalid_redirect_uri", f"Only loopback http redirect URIs are allowed: {bad}"
            )

        auth_method = body.get("token_endpoint_auth_method", "none")
        if auth_method != "none":
            return _error(
                400, "invalid_client_metadata", "Only public clients (token_endpoint_auth_method=none)"
            )

        raw_name = body.get("client_name") if isinstance(body.get("client_name"), str) else "mcp-client"
        name = _NAME_BAD_CHARS.sub("_", raw_name).strip()[:100] or "mcp-client"

        params = dict(
            UserPoolId=settings.pool_id,
            ClientName=f"dcr-{name}",
            GenerateSecret=False,
            AllowedOAuthFlowsUserPoolClient=True,
            AllowedOAuthFlows=["code"],
            AllowedOAuthScopes=settings.login_scopes,
            SupportedIdentityProviders=[settings.idp_name],
            CallbackURLs=redirect_uris,
            ExplicitAuthFlows=["ALLOW_REFRESH_TOKEN_AUTH"],
            RefreshTokenValidity=30,
            AccessTokenValidity=60,
            IdTokenValidity=60,
            TokenValidityUnits={"RefreshToken": "days", "AccessToken": "minutes", "IdToken": "minutes"},
            EnableTokenRevocation=True,
            PreventUserExistenceErrors="ENABLED",
        )
        try:
            resp = await anyio.to_thread.run_sync(
                lambda: cognito().create_user_pool_client(**params)
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = e.response.get("Error", {}).get("Message", "")
            log.warning("CreateUserPoolClient failed: %s %s", code, msg)
            if code in ("LimitExceededException", "TooManyRequestsException"):
                return _error(429, "temporarily_unavailable", "Client registration limit reached")
            if code == "InvalidParameterException":
                return _error(400, "invalid_client_metadata", msg or "Rejected by identity provider")
            return _error(500, "server_error", "Client registration failed")
        except Exception:
            log.exception("CreateUserPoolClient failed")
            return _error(500, "server_error", "Client registration failed")

        client_id = resp["UserPoolClient"]["ClientId"]
        log.info("DCR created Cognito client %s (%s) for %s", client_id, name, redirect_uris)
        return JSONResponse(
            {
                "client_id": client_id,
                "client_id_issued_at": int(time.time()),
                "client_name": raw_name,
                "redirect_uris": redirect_uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": " ".join(settings.login_scopes),
            },
            status_code=201,
            headers={"Cache-Control": "no-store"},
        )
