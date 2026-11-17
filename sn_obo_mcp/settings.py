"""Settings loaded from the environment (and ~/sn-obo.env). Secrets never logged."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(v.strip() for v in (value or "").split(",") if v.strip())


@dataclass(frozen=True)
class Settings:
    aws_region: str
    pool_id: str
    cog_url: str  # Cognito hosted domain, e.g. https://x.auth.us-east-1.amazoncognito.com
    sn_url: str  # ServiceNow instance URL
    obo_client_id: str
    obo_client_secret: str = field(repr=False)
    aws_profile: str | None = None
    base_url: str = "http://localhost:8000"
    host: str = "127.0.0.1"
    port: int = 8000
    m2m_client_ids: tuple[str, ...] = ()
    dcr_redirect_allowlist: tuple[str, ...] = ()
    idp_name: str = "EntraID"
    user_scope: str = "servicenow-api/access"
    m2m_scope: str = "mcp-m2m/invoke"
    obo_audience: str = "servicenow-api"
    authorize_prompt: str = "login"  # added to /authorize unless the client sent prompt; "" disables

    @property
    def issuer(self) -> str:
        return f"https://cognito-idp.{self.aws_region}.amazonaws.com/{self.pool_id}"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def login_scopes(self) -> list[str]:
        return ["openid", "email", "profile", self.user_scope]

    @property
    def m2m_enabled(self) -> bool:
        return bool(self.m2m_client_ids)

    @classmethod
    def from_env(cls, env_file: str | None = None) -> Settings:
        path = Path(env_file or os.environ.get("SN_OBO_ENV", "~/sn-obo.env")).expanduser()
        if path.exists():
            # Real environment wins over the file; handles `export K=V` lines.
            load_dotenv(path, override=False)
        e = os.environ

        def req(key: str) -> str:
            v = e.get(key)
            if not v:
                raise RuntimeError(f"Missing required setting {key} (env or {path})")
            return v

        return cls(
            aws_region=e.get("AWS_REGION", "us-east-1"),
            pool_id=req("POOL_ID"),
            cog_url=req("COG_URL").rstrip("/"),
            sn_url=req("SN").rstrip("/"),
            obo_client_id=req("OBO_ID"),
            obo_client_secret=req("OBO_SECRET"),
            aws_profile=e.get("AWS_PROFILE") or None,
            base_url=e.get("BASE_URL", "http://localhost:8000").rstrip("/"),
            host=e.get("HOST", "127.0.0.1"),
            port=int(e.get("PORT", "8000")),
            m2m_client_ids=_csv(e.get("M2M_CLIENT_IDS")),
            dcr_redirect_allowlist=_csv(e.get("DCR_REDIRECT_ALLOWLIST")),
            idp_name=e.get("IDP_NAME", "EntraID"),
            user_scope=e.get("USER_SCOPE", "servicenow-api/access"),
            m2m_scope=e.get("M2M_SCOPE", "mcp-m2m/invoke"),
            obo_audience=e.get("OBO_AUDIENCE", "servicenow-api"),
            authorize_prompt=e.get("AUTHORIZE_PROMPT", "login"),
        )
