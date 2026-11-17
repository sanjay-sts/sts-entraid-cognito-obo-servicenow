# sn-obo-mcp

Stateless [FastMCP](https://gofastmcp.com) 4.1.4 MCP server that calls ServiceNow **as the signed-in user**. Each tool call performs a Cognito OAuth 2.0 token exchange (RFC 8693, on-behalf-of) and uses the resulting token against the ServiceNow Table API, so ServiceNow ACLs apply per user.

Identity chain: Microsoft Entra ID -> Amazon Cognito (OIDC federation) -> this MCP server -> ServiceNow (third-party ID token inbound integration).

Accepted callers (via `MultiAuth`):

- **PKCE public clients** (Claude Code, MCP Inspector): dynamic client registration, browser login, no pre-registered client ID.
- **Confidential clients** (agent backends): send the user's Cognito access token as Bearer.
- **M2M clients** (`client_credentials`): authenticated, but user tools refuse them (no user to exchange). Disabled until `M2M_CLIENT_IDS` is set.

Lab project. See [Security notes](#security-notes) and [Known gaps](#known-gaps).

## Architecture

```
MCP client                          this server (stateless)                  AWS / Entra / ServiceNow
-----------                         -----------------------                  ------------------------
POST /mcp  ------------------------> 401 WWW-Authenticate: scope="servicenow-api/access",
                                         resource_metadata=.../oauth-protected-resource/mcp
GET /.well-known/oauth-protected-resource/mcp -> authorization_servers=[BASE_URL]
GET /.well-known/oauth-authorization-server   -> facade, issuer=BASE_URL, S256,
                                         authorize=/authorize token=/token register=/register
POST /register ---------------------> DCR shim ---------------> cognito-idp CreateUserPoolClient
                                      (loopback redirect URIs only) (public client, code flow)
GET /authorize?...&resource=... ------> 302 to Cognito /oauth2/authorize
                                      (drops RFC 8707 `resource`, adds identity_provider=EntraID
                                       and prompt=login) ------> Cognito -> Entra login
        <---- redirect with code ------------------------------------------------'
POST /token (code + PKCE) -----------> form pass-through ------> Cognito /oauth2/token
                                      (drops `resource`)  <----- Cognito access token
POST /mcp  Bearer <Cognito access token>
        |-> verify JWT (JWKS, issuer, scope servicenow-api/access)
        |-> tool call -> OBO broker: POST Cognito /oauth2/token
        |       grant_type=token-exchange, client mcp-obo (Basic auth),
        |       audience=servicenow-api, scope=servicenow-api/access
        |       cached per (sha256(subject token), audience, scope) until exp-60s
        '-> GET/POST/PATCH ServiceNow /api/now/table/... with Bearer <OBO token>
                -> ServiceNow authenticates the user by `email` claim; ACLs apply
```

Nothing is stored except an in-process OBO token cache (a restart only means re-exchanging). `/authorize` and `/token` exist because Cognito honours RFC 8707 `resource` and then rejects custom scopes with `invalid_target`; MCP clients always send `resource`.

## Prerequisites

- `uv` and Python 3.13 (`requires-python >= 3.12`)
- AWS profile with `cognito-idp:CreateUserPoolClient` on the user pool (used by `/register`)
- Already provisioned (see [CLAUDE.md](CLAUDE.md) for the full lab values):
  - Cognito user pool with Entra ID OIDC IdP, resource server `servicenow-api` (scope `access`)
  - Exchanger client `mcp-obo` (confidential, `ALLOW_TOKEN_EXCHANGE_IMPERSONATION`)
  - Pre-token Lambda (V3_0) adding a lowercase `email` claim on token exchange
  - ServiceNow inbound integration "Third party ID token" (client ID `servicenow-api`, user claim `email`, auth scope covering the Table API)
- Secrets in `~/sn-obo.env` (never commit)

## Configuration

Loaded from the environment, then from `~/sn-obo.env` (override path with `SN_OBO_ENV`; real environment wins over the file).

| Key | Required | Default | Purpose |
|---|---|---|---|
| `POOL_ID` | yes | | Cognito user pool ID (issuer and JWKS derive from it) |
| `COG_URL` | yes | | Cognito hosted domain URL |
| `SN` | yes | | ServiceNow instance URL |
| `OBO_ID` / `OBO_SECRET` | yes | | `mcp-obo` client credentials for token exchange |
| `AWS_REGION` | no | `us-east-1` | Region |
| `AWS_PROFILE` | no | default chain | Profile for boto3 (DCR) |
| `BASE_URL` | no | `http://localhost:8000` | Public URL; metadata issuer |
| `HOST` / `PORT` | no | `127.0.0.1` / `8000` | Bind address |
| `M2M_CLIENT_IDS` | no | empty (M2M off) | Comma-separated Cognito client IDs accepted as machines |
| `DCR_REDIRECT_ALLOWLIST` | no | empty | Extra non-loopback redirect URIs allowed in `/register` |
| `IDP_NAME` | no | `EntraID` | Cognito IdP name for DCR clients and `/authorize` |
| `USER_SCOPE` | no | `servicenow-api/access` | Required scope for user tokens; also used in exchange |
| `M2M_SCOPE` | no | `mcp-m2m/invoke` | Required scope for M2M tokens |
| `OBO_AUDIENCE` | no | `servicenow-api` | Exchange `audience` |
| `AUTHORIZE_PROMPT` | no | `login` | `prompt` added to `/authorize` if the client sent none; empty disables |

## Run and test

```bash
uv sync
uv run python server.py        # http://127.0.0.1:8000, MCP at /mcp
uv run pytest -q               # 55 tests, offline (sockets blocked), ~2.6 s
```

## Connect

- **MCP Inspector**: transport Streamable HTTP, URL `http://localhost:8000/mcp`, leave client ID empty, then run the OAuth flow. Details in [docs/runbook.md](docs/runbook.md).
- **Claude Code**: `claude mcp add --transport http servicenow-obo http://localhost:8000/mcp`, then `/mcp` to authenticate (not yet tested, see [acceptance record](docs/acceptance-2026-11-16.md)).

## Tools

All user tools refuse M2M callers.

| Tool | ServiceNow call | Notes |
|---|---|---|
| `auth_info(check_obo)` | none (optional exchange) | Diagnostic: caller kind, client id, scopes; `check_obo` returns decoded OBO claims |
| `whoami` | GET `sys_user` where `sys_id=javascript:gs.getUserID()` | Returns SN user and OBO claims |
| `incident_list(only_active, limit, contains)` | GET `incident` | Limit 1-50; ACLs filter rows |
| `incident_create(short_description, description, urgency)` | POST `incident` | `caller_id` is the sys_id from the whoami lookup; description prefixed `[via MCP agent]` |
| `incident_add_work_note(number, note)` | GET sys_id, PATCH `incident` `work_notes` | Number must match `INC####`; note prefixed |
| `kb_search(query, limit)` | GET `kb_knowledge` (`workflow_state=published`) | Empty query lists all |
| `kb_get_article(number)` | GET `kb_knowledge` by number | Includes `text` |
| `change_list(limit)` | GET `change_request` | |
| `change_create_normal(...)` | POST `change_request` (`type=normal`) | Needs change-author rights (ACL); prefixed |

## Error mapping

| Condition | Message to caller |
|---|---|
| SN 401 | ServiceNow rejected the token (401). Please re-authenticate. |
| SN 403 | `ServiceNow ACL denied: <SN message>` |
| SN 404 / no row | Not found or not visible to you. |
| SN 429 / 5xx, network | temporarily unavailable / could not reach ServiceNow |
| Exchange `invalid_grant` | Session cannot be exchanged (expired, or login lacked `servicenow-api/access`); re-authenticate |
| Exchange `invalid_client`, `invalid_scope`, ... | Server token-exchange configuration error |
| M2M caller on user tool | Machine callers are not supported |

## Helper scripts

Curl-only path without an MCP client (needs `jq`, `openssl`, `GATE1_ID` in the env file):

- `scripts/login.sh <label>`: prints a PKCE authorize URL, you paste the code, saves the Cognito access token to `~/.cache/sn-obo/<label>.at` (mode 600).
- `scripts/call.sh <label> <tool> ['{"json":"args"}']`: calls a tool on `$BASE_URL/mcp` with the saved token.

## Layout

```
server.py                 app factory, loopback CORS, uvicorn entrypoint
sn_obo_mcp/settings.py    env config
sn_obo_mcp/auth.py        MultiAuth (users + optional machines), caller helpers
sn_obo_mcp/oauth_routes.py  AS metadata facade, /register, /authorize, /token, /health
sn_obo_mcp/obo.py         Cognito token-exchange broker with TTL cache
sn_obo_mcp/servicenow.py  Table API client, error mapping
sn_obo_mcp/tools.py       MCP tools
scripts/                  login.sh, call.sh
tests/                    offline pytest suite
docs/                     runbook.md, acceptance-2026-11-16.md
CLAUDE.md                 lab facts and design decisions
```

## Known gaps

Details and evidence in [docs/acceptance-2026-11-16.md](docs/acceptance-2026-11-16.md).

- Lidia (SG-SN-Security) gets 0 results from `kb_search`; `kb_knowledge` returns no rows via the Table API even unfiltered. Appears to be ServiceNow-side.
- Not yet run: Claude Code client, M2M tokens (`mcp-m2m` resource server not created), M2M -> ServiceNow.
- Stale `dcr-*` Cognito clients accumulate; no automatic cleanup.

## Security notes

- Secrets only in `~/sn-obo.env` or the environment; never in code or git. Tokens are never logged (only user name and a short hash prefix).
- `/register` only issues public clients with loopback `http://localhost|127.0.0.1` redirects unless allowlisted.
- CORS is limited to loopback origins; bearer tokens only, no cookies.
- `/authorize` forces `prompt=login` by default so users can switch accounts.
- Lab-only: plain HTTP, no WAF or rate limit on `/register`, no DCR client cleanup, impersonation (no `act` claim).
