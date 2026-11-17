# CLAUDE.md — sn-obo-mcp: FastMCP 4 MCP server with Cognito OBO to ServiceNow

## Goal
Build a FastMCP **4.1.x** (Python) MCP server that:
1. Accepts three caller types via `MultiAuth`:
   - **PKCE public clients** (Claude Code, MCP Inspector) — users log in via browser, no pre-registered client ID (DCR).
   - **Confidential clients** (agent backends acting for a user) — send the user's Cognito access token as Bearer.
   - **M2M clients** (pipelines, `client_credentials`) — no user.
2. For user callers, performs **Cognito OAuth 2.0 token exchange (RFC 8693, on-behalf-of)** per tool call and calls ServiceNow **as the user**, so ServiceNow ACLs apply.
3. Is **stateless** (no token store; only thin stateless /authorize and /token pass-throughs that strip RFC 8707 `resource`). Single instance is fine for the lab.

## Everything below is PROVEN in the lab (2026-11-16) unless marked TODO

### Environment (non-secret values; secrets live in `~/sn-obo.env`, never commit)
| Item | Value |
|---|---|
| AWS profile / region | `admin` / `us-east-1` (account 590894668881) |
| Cognito user pool | `us-east-1_u9Q54aSvN` (tier **ESSENTIALS**) |
| Cognito domain | `https://sn-obo-2tdgcb.auth.us-east-1.amazoncognito.com` |
| Issuer / JWKS | `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_u9Q54aSvN` (+ `/.well-known/jwks.json`) |
| Cognito IdP | `EntraID` (OIDC → Entra tenant `8f691e3d-b425-41ae-a2c9-3f1a4832d55c`, app `Cognito-Federation` `5e7d536e-…`) |
| Attribute mapping | `email=email, custom:upn=preferred_username, custom:entra_oid=oid` |
| Resource server | `servicenow-api`, scope **`access`** (→ `servicenow-api/access`) |
| Login client (test) | `gate1-test` `5s5dktbkb7bcovb5510vib4s7t` — public, code+PKCE, callback `http://localhost:6274/oauth/callback`, scopes `openid email profile servicenow-api/access` |
| Exchanger client | `mcp-obo` `njs5uq6vuorsagsb3meb8cn3f` — confidential, `ExplicitAuthFlows=[ALLOW_TOKEN_EXCHANGE_IMPERSONATION]`, `AllowedOAuthFlows=[client_credentials]` (only to satisfy validation), scope `servicenow-api/access` |
| Pre-token Lambda | `sn-obo-pretoken` attached as **V3_0**; on `TokenGeneration_TokenExchange` adds `email` claim (lowercased) |
| ServiceNow | `https://dev483791.service-now.com` (PDI, **Brazil** release) |
| SN inbound integration | **System OAuth → Inbound Integrations → Third party ID token** `Cognito-OBO-v2`: client ID `servicenow-api`, OIDC provider `Cognito us-east-1` (metadata URL above), user claim `email` → user field Email, JTI off, auth scope **`sn_obo_table` → Table API**, "Allow access only to APIs in selected scope" ON |
| Env file keys | `AWS_PROFILE AWS_REGION TENANT TENANT_ID COG_DOMAIN COG_URL SN ENTRA_APP_ID ENTRA_SECRET POOL_ID GATE1_ID OBO_ID OBO_SECRET LAMBDA_ARN`. Optional server settings: `BASE_URL` (default http://localhost:8000), `M2M_CLIENT_IDS`, `DCR_REDIRECT_ALLOWLIST`, `AUTHORIZE_PROMPT` (default `login`) |
| Reference script | `~/obo-test.sh <label>` — full PKCE login → exchange → ServiceNow calls (works) |

### Proven token-exchange request (copy this exactly)
```
POST {COG_URL}/oauth2/token   (HTTP Basic: OBO_ID:OBO_SECRET)
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<user's Cognito access token>
subject_token_type=urn:ietf:params:oauth:token-type:access_token
audience=servicenow-api
scope=servicenow-api/access
```
Result: access token with `aud=servicenow-api`, same `sub`/`username`, `scope=servicenow-api/access`, `email=<user>`, **no refresh token**, `expires_in` capped at the subject token's remaining life.
Then: `Authorization: Bearer <obo token>` to ServiceNow REST → authenticated as the user.

### Proven results (ServiceNow ACLs over OBO)
| User | `[LAB]` incidents via Table API |
|---|---|
| AdeleV (SG-SN-ServiceDesk, itil) | 6 (+ created INC0010007, `sys_created_by=AdeleV@…`) |
| AlexW (SG-SN-Network, u_network_agent) | 3 (INC0010001-0003) |
| DiegoS (SG-SN-Employees, no role) | 1 (INC0010006) |
Other personas: MeganB (SG-SN-ChangeMgmt: itil + u_change_author → may create changes; ACL C1 Deny-Unless blocks others), LidiaH (SG-SN-Security → Security Runbooks KB via user criteria).

### MCP server acceptance results (2026-11-16)
Full record: [docs/acceptance-2026-11-16.md](docs/acceptance-2026-11-16.md). 55 offline tests pass; live checks:
- Inspector DCR + PKCE end to end works (after the `/authorize` + `/token` fix and loopback CORS); `prompt=login` enables user switching.
- Adele whoami OK; OBO cache hit on second call; incident_create -> INC0010009 as Adele; Adele incident_list = 8.
- Alex = 3 [LAB] incidents, Diego = 1; Megan created CHG0030007; Adele change_create_normal -> ACL denied.
- Stateless restart mid-session OK; DCR rejects non-loopback redirects (400); unauthenticated /mcp -> 401 with scope + resource_metadata.
- **GAP (open):** Lidia `kb_search` returns 0 (expected Security Runbooks). Her OBO token is correct and `kb_knowledge_base` is readable, but `kb_knowledge` via Table API returns [] even unfiltered; UI impersonation can read KB0010001. ServiceNow-side issue, no MCP change needed.
- Not run: Claude Code client, M2M tests (`mcp-m2m` not created), Diego work-note check.

### Hard-won lessons (do not re-learn)
- Token exchange with **no scope** → `invalid_grant`. User login token **must** include `servicenow-api/access` (exchange only down-scopes).
- Cognito **access tokens never contain `email`**; the V2/V3 pre-token Lambda adds it. ServiceNow maps on `email`.
- `get_derived_token` is **not** in AWS CLI 2.40.3 or current boto3 → use the `/oauth2/token` endpoint.
- Cognito client with `AllowedOAuthScopes` requires at least one `AllowedOAuthFlows` → `client_credentials` on `mcp-obo`.
- ServiceNow (Brazil): the **deprecated** Application Registry "OIDC provider" path logs `kaa_wrapper_required … bare-bearer delivery is not accepted`. The **new Inbound Integrations** path works with plain Bearer. That KAA log line still appears (legacy loader) but is harmless — requests authenticate as the user.
- ServiceNow "Securely scoped" → 403 `Access to unscoped api is not allowed` unless the auth scope lists the API (Table API). Add more APIs (e.g. Change Management, Knowledge) to `sn_obo_table` or new scopes if tools need them.
- Entra tenant requires **admin consent** for `Cognito-Federation` (openid, email, profile, User.Read) — done.
- Use `prompt=login` + private windows when switching test users.
- **Cognito honours RFC 8707 `resource`** (MCP clients always send `resource=<base>/mcp`): it then requires every custom scope to belong to a resource server with that identifier → `invalid_target: custom scopes requested for resource-binding must be assigned to the resource being requested`. Fix: metadata points `authorization_endpoint`/`token_endpoint` at our stateless `/authorize` (302 to Cognito minus `resource`, adds `identity_provider=EntraID`) and `/token` (form pass-through minus `resource`). Verified live 2026-11-16.
- Browser MCP clients (Inspector) need CORS on discovery, `/register`, `/token`, `/mcp` → loopback-origin CORSMiddleware in `server.py`.

## Architecture to build
```
MCP client (Claude Code / Inspector)                      Agent backend (confidential)      Pipeline (M2M)
   │ DCR → /register (shim creates Cognito public client)    │ user's Cognito access token       │ client_credentials token
   │ GET /authorize (302 → Cognito, minus `resource`) → Entra │                                   │
   │ POST /token (form pass-through → Cognito, minus `resource`) │                                │
   └──────────── Bearer: user Cognito access token ───────────┴───────────── Bearer ──────────────┘
                                         ▼
                     FastMCP 4 server (stateless resource server)
                     MultiAuth(server=RemoteAuthProvider(users verifier),
                               verifiers={"machines": m2m verifier})
                     /.well-known/oauth-authorization-server (static facade: authorize/token → BASE_URL pass-throughs, revoke → Cognito, S256)
                     /authorize, /token (stateless pass-throughs, strip RFC 8707 `resource`)
                     /register (DCR shim → cognito-idp:CreateUserPoolClient)
                     /health
                                         ▼ per tool call (users only)
                     OBO broker → Cognito /oauth2/token (token-exchange, mcp-obo)
                                         ▼
                     ServiceNow REST (Bearer OBO token) → ACLs as the user
```

### FastMCP 4.1.4 APIs (verified by inspecting the installed package)
- `from fastmcp.server.auth import MultiAuth, RemoteAuthProvider`
- `from fastmcp.server.auth.providers.aws import AWSCognitoTokenVerifier` — validates `client_id` only if `audience` is set; claims filtered to `sub`, `username`, `cognito:groups`.
- `RemoteAuthProvider(token_verifier, authorization_servers, base_url, scopes_supported=None, challenge_scopes=None, ...)`
- `MultiAuth(server=..., verifiers={name: verifier} | [verifiers], ...)` — tries server, then verifiers in order.
- `mcp.custom_route(path, methods=[...])`, `mcp.http_app(stateless_http=True, ...)`
- In tools: `get_access_token().token` = raw caller token; `.client_id`; `.claims`.
- FastMCP 4 uses `httpx2` internally; add `httpx` explicitly if used.
- Unauthenticated `/mcp` returns 401 with `WWW-Authenticate: … scope="…", resource_metadata="…/.well-known/oauth-protected-resource/mcp"` (scope from `challenge_scopes`).

### Verified against installed fastmcp 4.1.4 (2026-11-16, Step 0 probe)
- `MultiAuth(verifiers={name: v})` dict works; `server_source_id="users"` names the server source.
- MultiAuth **rewrites `AccessToken.client_id`** to a JSON-qualified id (`["users","<cid>",null,"<sub>"]`); the real Cognito client id is `token.original_client_id`.
- MultiAuth inherits the server's `required_scopes` and `/mcp` enforces them → M2M tokens would 403. We pass `required_scopes=[]` (each verifier enforces its own). That also empties the 401 `scope=`, so `sn_obo_mcp/auth.py` subclasses MultiAuth to override `get_challenge_scopes()` → `servicenow-api/access`.
- `JWTVerifier` has no `token_use` check; ID tokens are rejected only because they lack the required scope. JWKS seam for tests: `JWTVerifier._fetch_jwks` (uses `httpx2`). `RSAKeyPair.generate()/create_token()` exist for tests.
- Routes: RemoteAuthProvider serves only `/.well-known/oauth-protected-resource/mcp`; custom routes (metadata, /register, /health) are appended after `/mcp`, no collision. Host/Origin guard is off by default in `http_app` (Inspector origin `localhost:6274` OK).
- Stateless `tools/call` works without `initialize`. Tests use the anyio pytest plugin (pytest-asyncio breaks the lifespan cancel scope across tasks).

### Auth design decisions
- **Users verifier**: `AWSCognitoTokenVerifier(jwks_uri, issuer=ISS, required_scopes=["servicenow-api/access"])`, no `audience` (DCR client IDs are dynamic). Accepts PKCE and confidential-client user tokens alike.
- **Machines verifier**: separate `AWSCognitoTokenVerifier(..., audience=[M2M client IDs], required_scopes=["mcp-m2m/invoke"])`. TODO: create resource server `mcp-m2m` scope `invoke` + one test M2M client.
- **Distinguish caller**: M2M tokens have no `username` claim. Tools that act for a user must refuse M2M callers (exchange needs a user subject).
- **DCR shim** (`/register`): `CreateUserPoolClient` public, `AllowedOAuthFlows=[code]`, scopes `openid email profile servicenow-api/access`, `SupportedIdentityProviders=[EntraID]`, `CallbackURLs` = **loopback only** (http://localhost|127.0.0.1) unless in an explicit allowlist; refresh 30d, access/id 60m; returns RFC 7591 JSON 201. Needs IAM `cognito-idp:CreateUserPoolClient` on the pool. Open items: rate limit (WAF), cleanup of stale `dcr-*` clients, app-client quota — defer.
- **AS metadata facade**: issuer = BASE_URL; authorization_endpoint/token_endpoint → BASE_URL `/authorize` and `/token` (stateless pass-throughs to Cognito that strip `resource`; `/authorize` adds `identity_provider` and `prompt=login`); revoke → Cognito domain; `registration_endpoint` = BASE_URL/register; `code_challenge_methods_supported: ["S256"]` (Cognito's own discovery omits it); `token_endpoint_auth_methods_supported: ["none"]`.
- **OBO broker**: cache exchanged token per (sha256(subject token), audience, scopes) until exp−60s; impersonation (no actor). Optional later: delegation with `mcp-actor` client → `act` claim (needs `ALLOW_TOKEN_EXCHANGE_DELEGATION` + resource server `mcp-actor/act`).
- **M2M → ServiceNow** (TODO, later): token exchange needs a user, so M2M uses ServiceNow's inbound **client credentials** grant with a dedicated integration user per pipeline.

## Tools to implement (3 modules + diagnostics)
| Tool | ServiceNow call | Notes |
|---|---|---|
| `whoami` | GET `/api/now/table/sys_user?sysparm_query=sys_id=javascript:gs.getUserID()` | Return SN user + decoded OBO claims |
| `incident_list(only_active, limit)` | GET `/api/now/table/incident` | ACLs filter rows |
| `incident_create(short_description, description, urgency)` | POST `/api/now/table/incident` | caller_id = sys_id looked up via the whoami query (`javascript:gs.getUserID()` does not evaluate in POST bodies) |
| `incident_add_work_note(number, note)` | lookup sys_id → PATCH work_notes | 403 → readable ACL error |
| `kb_search(query, limit)` / `kb_get_article(number)` | GET `/api/now/table/kb_knowledge` (workflow_state=published) | user criteria hide Security Runbooks |
| `change_list(limit)` | GET `/api/now/table/change_request` | |
| `change_create_normal(...)` | POST `/api/now/table/change_request` (type=normal) or `/api/sn_chg_rest/change/normal` | If using sn_chg_rest, add that API to the SN auth scope. Deny-Unless ACL C1: only u_change_author |
Map HTTP 401 → "token rejected", 403 → "ServiceNow ACL denied", 404/empty → "not found or not visible to you". Prefix created records with "[via MCP agent]".

## Test plan (acceptance)
1. `uv run python server.py` → MCP Inspector (Streamable HTTP `http://localhost:8000/mcp`, leave client ID empty) → DCR + PKCE login as Adele → `whoami` = Adele Vance. ✅
2. `claude mcp add --transport http servicenow-obo http://localhost:8000/mcp` → `/mcp` authenticate. ⏳ not run
3. Per user via tools: Adele 6+ incidents, Alex 3, Diego 1; Megan can `change_create_normal`, Adele gets ACL denied; Lidia sees Security Runbooks, Adele does not. ✅ Adele/Alex/Diego/Megan; ❌ gap: Lidia kb_search returns 0 (see acceptance doc)
4. Restart server mid-session → next tool call works without re-login (stateless). ✅
5. M2M token → user tools refuse; unknown-pool token → 401. ⏳ M2M not run (`mcp-m2m` not created); tampered token → 401 ✅

## Constraints / preferences
- Pin `fastmcp==4.1.4`. Python 3.12+, `uv`. Secrets from env (`~/sn-obo.env`), never in code or git.
- Prefer empirical validation: write small tests/scripts before large code.
- Keep it simple for the lab; production hardening (WAF, DCR cleanup, delegation/act, HTTPS on ALB) is a later phase.

## Repo layout
- `server.py` — app factory, CORS, uvicorn entrypoint
- `sn_obo_mcp/{settings,auth,oauth_routes,obo,servicenow,tools}.py` — env config; MultiAuth + caller helpers; metadata/DCR/authorize/token/health routes; OBO broker; ServiceNow REST client; MCP tools
- `scripts/{login,call}.sh` — curl-based PKCE login and tool call
- `tests/` — offline pytest suite (55 tests)
- `docs/` — runbook, acceptance record
