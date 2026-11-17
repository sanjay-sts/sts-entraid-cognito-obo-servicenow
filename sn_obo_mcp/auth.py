"""Token verification: Cognito user tokens (PKCE / confidential) + M2M tokens via MultiAuth."""

from __future__ import annotations

from dataclasses import dataclass

from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken, MultiAuth, RemoteAuthProvider
from fastmcp.server.auth.providers.aws import AWSCognitoTokenVerifier
from fastmcp.server.dependencies import get_access_token

from .settings import Settings


class _ScopedChallengeMultiAuth(MultiAuth):
    """MultiAuth with no route-level scope gate but a fixed 401 challenge scope.

    MultiAuth inherits the server's required_scopes and enforces them on /mcp, which would
    403 M2M tokens (they carry mcp-m2m/invoke, not servicenow-api/access). We pass
    required_scopes=[] (each verifier enforces its own scopes) and keep advertising the
    user scope in WWW-Authenticate so MCP clients request it at login.
    """

    def __init__(self, *, challenge: list[str], **kwargs):
        super().__init__(**kwargs)
        self._challenge = challenge

    def get_challenge_scopes(self, required_scopes: list[str] | None = None) -> list[str]:
        return self._challenge if not required_scopes else required_scopes


def build_auth(settings: Settings) -> MultiAuth:
    users = AWSCognitoTokenVerifier(
        jwks_uri=settings.jwks_uri,
        issuer=settings.issuer,
        required_scopes=[settings.user_scope],
        # no audience: DCR client IDs are dynamic
    )
    server = RemoteAuthProvider(
        users,
        authorization_servers=[settings.base_url],  # our metadata facade, not Cognito
        base_url=settings.base_url,
        scopes_supported=[settings.user_scope],
        challenge_scopes=[settings.user_scope],
    )
    verifiers = {}
    if settings.m2m_enabled:
        verifiers["machines"] = AWSCognitoTokenVerifier(
            jwks_uri=settings.jwks_uri,
            issuer=settings.issuer,
            audience=list(settings.m2m_client_ids),
            required_scopes=[settings.m2m_scope],
        )
    return _ScopedChallengeMultiAuth(
        server=server,
        verifiers=verifiers or None,
        server_source_id="users",
        required_scopes=[],
        challenge=[settings.user_scope],
    )


@dataclass(frozen=True)
class Caller:
    kind: str  # "user" | "machine"
    token: AccessToken

    @property
    def client_id(self) -> str:
        return self.token.original_client_id or self.token.client_id

    @property
    def username(self) -> str | None:
        return self.token.claims.get("username")


def current_caller() -> Caller:
    token = get_access_token()
    if token is None:
        raise ToolError("Not authenticated")
    # M2M (client_credentials) access tokens have no `username` claim.
    kind = "user" if token.claims.get("username") else "machine"
    return Caller(kind=kind, token=token)


def require_user() -> Caller:
    caller = current_caller()
    if caller.kind != "user":
        raise ToolError(
            "This tool acts on behalf of a signed-in user; machine (M2M) callers are not supported."
        )
    return caller
