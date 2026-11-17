"""MCP tools. User tools exchange the caller's token (OBO) and call ServiceNow as that user."""

from __future__ import annotations

import re
from typing import Annotated

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from .auth import current_caller, require_user
from .obo import OboBroker, jwt_claims
from .servicenow import ServiceNowClient, ServiceNowError, safe_query_text

PREFIX = "[via MCP agent] "
INC_RE = re.compile(r"^INC\d{4,}$")
KB_RE = re.compile(r"^KB\d{4,}$")

INCIDENT_FIELDS = ["number", "short_description", "state", "priority", "urgency", "caller_id",
                   "assigned_to", "assignment_group", "sys_created_by", "sys_created_on"]
KB_FIELDS = ["number", "short_description", "kb_knowledge_base", "kb_category", "sys_updated_on"]
CHANGE_FIELDS = ["number", "short_description", "type", "state", "risk", "assigned_to",
                 "assignment_group", "sys_created_by", "sys_created_on"]

Limit = Annotated[int, Field(ge=1, le=50, description="Max rows (1-50)")]


def register_tools(mcp: FastMCP, broker: OboBroker, sn: ServiceNowClient) -> None:
    async def obo_token() -> str:
        caller = require_user()
        return await broker.exchange(caller.token.token)

    async def my_user(token: str) -> dict:
        rows = await sn.table_get(token, "sys_user", query="sys_id=javascript:gs.getUserID()",
                                  fields=["sys_id", "name", "user_name", "email"], limit=1,
                                  display_value=False)
        if not rows:
            raise ServiceNowError("ServiceNow could not resolve your user (no matching sys_user).")
        return rows[0]

    def norm_number(value: str, pattern: re.Pattern, kind: str) -> str:
        v = value.strip().upper()
        if not pattern.match(v):
            raise ToolError(f"Invalid {kind} number: {value!r}")
        return v

    # ---- diagnostics -------------------------------------------------------

    @mcp.tool
    async def auth_info(check_obo: bool = False) -> dict:
        """Show how the server sees the caller (user vs machine, client id, scopes). Diagnostic.

        check_obo=true also performs the on-behalf-of token exchange (users only) and returns
        the decoded claims of the resulting ServiceNow token.
        """
        c = current_caller()
        info = {
            "kind": c.kind, "client_id": c.client_id, "username": c.username,
            "sub": c.token.claims.get("sub"), "groups": c.token.claims.get("cognito:groups", []),
            "scopes": c.token.scopes, "expires_at": c.token.expires_at,
        }
        if check_obo:
            claims = jwt_claims(await obo_token())
            info["obo"] = {k: claims.get(k) for k in ("aud", "email", "scope", "username", "client_id", "exp")}
        return info

    @mcp.tool
    async def whoami() -> dict:
        """Return the ServiceNow user this session acts as (via on-behalf-of token exchange)."""
        token = await obo_token()
        claims = jwt_claims(token)
        return {
            "servicenow_user": await my_user(token),
            "obo_token": {k: claims.get(k) for k in ("aud", "email", "scope", "exp")},
        }

    # ---- incidents ----------------------------------------------------------

    @mcp.tool
    async def incident_list(only_active: bool = True, limit: Limit = 20,
                            contains: str | None = None) -> dict:
        """List incidents visible to you (ServiceNow ACLs apply). Optionally filter short_description."""
        token = await obo_token()
        q = []
        if only_active:
            q.append("active=true")
        if contains and safe_query_text(contains):
            q.append(f"short_descriptionLIKE{safe_query_text(contains)}")
        q.append("ORDERBYDESCsys_created_on")
        rows = await sn.table_get(token, "incident", query="^".join(q), fields=INCIDENT_FIELDS, limit=limit)
        return {"count": len(rows), "incidents": rows}

    @mcp.tool
    async def incident_create(
        short_description: Annotated[str, Field(min_length=3, max_length=150)],
        description: str = "",
        urgency: Annotated[int, Field(ge=1, le=3, description="1=High 2=Medium 3=Low")] = 3,
    ) -> dict:
        """Create an incident with you as the caller."""
        token = await obo_token()
        me = await my_user(token)
        body = {"short_description": PREFIX + short_description, "description": description,
                "urgency": str(urgency), "caller_id": me["sys_id"]}
        rec = await sn.table_create(token, "incident", body,
                                    fields=["number", "sys_id", *INCIDENT_FIELDS[1:]])
        return {"created": rec}

    @mcp.tool
    async def incident_add_work_note(number: str, note: Annotated[str, Field(min_length=1, max_length=4000)]) -> dict:
        """Add a work note to an incident (e.g. INC0010001)."""
        num = norm_number(number, INC_RE, "incident")
        token = await obo_token()
        rows = await sn.table_get(token, "incident", query=f"number={num}", fields=["sys_id", "number"],
                                  limit=1, display_value=False)
        if not rows:
            raise ServiceNowError(f"Incident {num} not found or not visible to you.")
        rec = await sn.table_patch(token, "incident", rows[0]["sys_id"], {"work_notes": PREFIX + note},
                                   fields=["number", "sys_updated_by", "sys_updated_on"])
        return {"updated": rec}

    # ---- knowledge ----------------------------------------------------------

    @mcp.tool
    async def kb_search(query: str = "", limit: Limit = 10) -> dict:
        """Search published knowledge articles you can read (user criteria apply). Empty query lists all."""
        token = await obo_token()
        q = "workflow_state=published"
        text = safe_query_text(query)
        if text:
            q += f"^short_descriptionLIKE{text}^ORtextLIKE{text}"
        rows = await sn.table_get(token, "kb_knowledge", query=q + "^ORDERBYnumber", fields=KB_FIELDS, limit=limit)
        return {"count": len(rows), "articles": rows}

    @mcp.tool
    async def kb_get_article(number: str) -> dict:
        """Get a published knowledge article (e.g. KB0010001) including its text."""
        num = norm_number(number, KB_RE, "knowledge article")
        token = await obo_token()
        rows = await sn.table_get(token, "kb_knowledge", query=f"number={num}^workflow_state=published",
                                  fields=[*KB_FIELDS, "text"], limit=1)
        if not rows:
            raise ServiceNowError(f"Article {num} not found or not visible to you.")
        return rows[0]

    # ---- change -------------------------------------------------------------

    @mcp.tool
    async def change_list(limit: Limit = 20) -> dict:
        """List change requests visible to you."""
        token = await obo_token()
        rows = await sn.table_get(token, "change_request", query="ORDERBYDESCsys_created_on",
                                  fields=CHANGE_FIELDS, limit=limit)
        return {"count": len(rows), "changes": rows}

    @mcp.tool
    async def change_create_normal(
        short_description: Annotated[str, Field(min_length=3, max_length=150)],
        description: str = "",
        justification: str = "",
        implementation_plan: str = "",
        backout_plan: str = "",
        test_plan: str = "",
    ) -> dict:
        """Create a normal change request (requires change-author rights in ServiceNow)."""
        token = await obo_token()
        body = {"type": "normal", "short_description": PREFIX + short_description, "description": description,
                "justification": justification, "implementation_plan": implementation_plan,
                "backout_plan": backout_plan, "test_plan": test_plan}
        rec = await sn.table_create(token, "change_request", body, fields=["sys_id", *CHANGE_FIELDS])
        return {"created": rec}
