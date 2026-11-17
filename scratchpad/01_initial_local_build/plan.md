# Plan: sn-obo-mcp (FastMCP 4.1.4, Cognito OBO to ServiceNow)

## Context
CLAUDE.md specifies a stateless FastMCP 4.1.4 server. It accepts three caller types: PKCE users (through DCR), confidential clients sending a user token, and M2M clients. For user callers it runs a Cognito RFC 8693 token exchange on every tool call and calls ServiceNow as that user. The repo has no code yet. We build in small steps, and I stop after each step so you can check it against real Cognito and ServiceNow.

## Model routing (Claude Code subagents)
- **Fable**: planning, and re-planning if a real-world check fails.
- **Opus**: API research (Step 0) and all code plus offline tests (Steps 1 to 4).
- **Sonnet**: `scripts/login.sh`, README and runbook, and the end-to-end acceptance runs.

## Facts established during planning
- uv 0.11.19 is installed. fastmcp 4.1.4 is not installed locally; only 3.4.11 is in the uv cache.
- Pin `.python-version` to 3.13, since 3.14 wheels are a risk.
- `~/sn-obo.env` uses `export K=V` lines and has `POOL_ID` duplicated. `python-dotenv` handles both.
- `~/obo-test.sh` is the proven PKCE, exchange and ServiceNow flow.

Design points to confirm in 4.1.4 (taken from the 3.4.11 source):
1. `MultiAuth` takes `required_scopes` from the server, so an M2M token would get 403 at `/mcp`. Fix: `MultiAuth(..., required_scopes=[])`, and let each verifier enforce its own scopes.
2. `RemoteAuthProvider.authorization_servers=[BASE_URL]`, so that clients read our metadata facade where `issuer == BASE_URL`.
3. A route added with `custom_route` at `/.well-known/oauth-authorization-server` does not collide with the protected-resource route.
4. Claims are filtered to `sub`, `username` and `cognito:groups`. A missing `username` means a machine caller. The users verifier, which has no audience, also accepts `mcp-obo` client_credentials tokens and OBO tokens, so the username check in user tools is mandatory.
5. `javascript:gs.getUserID()` only works inside query strings. `incident_create` therefore looks up the caller's `sys_id` first and sends that as `caller_id`.

## File layout
```
pyproject.toml   (fastmcp==4.1.4, httpx, boto3, python-dotenv; dev: pytest, pytest-asyncio, respx, cryptography)
.python-version  (3.13)
.gitignore       (.venv, *.env, caches)
server.py        create_app(settings) + uvicorn on http_app(stateless_http=True)
sn_obo_mcp/settings.py      frozen dataclass; load_dotenv(SN_OBO_ENV or ~/sn-obo.env)
sn_obo_mcp/auth.py          build_auth() -> MultiAuth; caller()/require_user()
sn_obo_mcp/oauth_routes.py  AS metadata facade, /register DCR shim, /health
sn_obo_mcp/obo.py           OboBroker (exchange + TTL cache)
sn_obo_mcp/servicenow.py    httpx client + error mapping
sn_obo_mcp/tools.py         auth_info, whoami, incident_*, kb_*, change_*
scripts/login.sh            PKCE login only (from obo-test.sh), saves the token to ~/.cache/sn-obo/<user>.at (0600)
tests/                      conftest + test_auth, test_oauth_routes, test_obo, test_servicenow, test_tools
```
Settings:
- From the env file: AWS_PROFILE, AWS_REGION, POOL_ID, COG_URL, SN, OBO_ID, OBO_SECRET.
- New, with defaults: BASE_URL=http://localhost:8000, HOST/PORT, M2M_CLIENT_IDS="" (csv, empty disables M2M), DCR_REDIRECT_ALLOWLIST="", IDP_NAME=EntraID, USER_SCOPE=servicenow-api/access, M2M_SCOPE=mcp-m2m/invoke, OBO_AUDIENCE=servicenow-api.
- Derived: ISSUER and JWKS_URI.
- Secrets are excluded from repr.

## Step 0: scaffold and verify APIs (Opus)
Run `uv sync`. Inspect the installed fastmcp for:
- the MultiAuth, RemoteAuthProvider and AWSCognitoTokenVerifier signatures;
- how the JWKS is fetched (this is the seam the tests patch);
- the `get_access_token` import path;
- route order and the host guard;
- whether stateless `tools/call` works without `initialize`.

Record the results as a "Verified 4.1.4 APIs" note in CLAUDE.md.

**You run:** `uv run python -c "import fastmcp; print(fastmcp.__version__)"`, then the read-only `aws cognito-idp describe-user-pool` / `list-user-pool-clients` / `list-resource-servers --profile admin`, then a curl of the JWKS.

## Step 1: auth (Opus)
**Verifiers and MultiAuth**
- Users verifier: `AWSCognitoTokenVerifier(jwks_uri, issuer, required_scopes=[USER_SCOPE])`.
- Machines verifier: built only if `M2M_CLIENT_IDS` is set, with `audience=ids` and `required_scopes=[M2M_SCOPE]`.
- `RemoteAuthProvider(users, authorization_servers=[BASE_URL], base_url, scopes_supported, challenge_scopes=[USER_SCOPE])`.
- `MultiAuth(server=…, verifiers=…, required_scopes=[])`.

**Metadata facade** (also served at `/.well-known/openid-configuration`)
- `issuer` is BASE_URL.
- authorize, token and revoke point at COG_URL.
- `registration_endpoint` is BASE_URL/register.
- `S256`, `token_endpoint_auth_methods_supported: ["none"]`.
- `scopes_supported` lists openid, email, profile and USER_SCOPE.

**`/register`**
- Accepts loopback `redirect_uris` only, or exact allowlist matches; anything else gets 400 `invalid_redirect_uri`.
- Calls boto3 `create_user_pool_client` in a worker thread with these settings: public client, flow `code`, scopes, `SupportedIdentityProviders=[EntraID]`, refresh 30d / access 60m / id 60m, token revocation on, and the name `dcr-<sanitized name>`.
- Returns an RFC 7591 201 response with no secret.
- Error mapping: Limit/TooManyRequests → 429, InvalidParameter → 400, anything else → 500 with no detail.

**`/health`** returns `{status, m2m_enabled}`.

**`auth_info` diagnostic tool**: returns kind, client_id, username, scopes and exp. It is allowed for M2M callers.

**You run:**
- `uv run python server.py`.
- Curl `/health`, the protected-resource metadata (`authorization_servers==[BASE_URL]`) and the AS metadata.
- Unauthenticated `POST /mcp` should return 401 with `scope` and `resource_metadata` in the header.
- `/register` with a good and a bad redirect, checking the result with `aws cognito-idp describe-user-pool-client` and then deleting the client.
- `scripts/login.sh adele`, then call `auth_info` with curl. A tampered token should get 401.
- MCP Inspector (empty client ID → DCR + PKCE) and `claude mcp add --transport http servicenow-obo http://localhost:8000/mcp`.

**M2M setup (you run once):**
- `aws cognito-idp create-resource-server --identifier mcp-m2m --scopes ScopeName=invoke,…`
- `create-user-pool-client mcp-m2m-test --generate-secret --allowed-o-auth-flows client_credentials --allowed-o-auth-scopes mcp-m2m/invoke`
- Add `M2M_ID`, `M2M_SECRET` and `M2M_CLIENT_IDS` to `~/sn-obo.env`, then get a client_credentials token. `auth_info` should report kind=machine; with `M2M_CLIENT_IDS` unset it should return 401.

**Things to watch for:**
- Cognito may reject `resource=` (RFC 8707) on authorize or token. The fallback is a stateless `/authorize` redirect that strips it.
- Cognito may reject `127.0.0.1` callbacks.
- The pre-token Lambda may break on client_credentials.

If any of these fail, Fable re-plans.

## Step 2: offline tests (Opus)
**conftest**
- Session RSA key, a JWKS and `mint(**claims)` that produces Cognito-shaped access tokens.
- A patch on the JWKS fetch at the seam found in Step 0.
- A `settings` fixture with no env file.
- `create_app` driven through `httpx.ASGITransport`, with lifespan run.
- A botocore `Stubber` for cognito-idp.
- `respx` for HTTP.
- An autouse fixture that blocks sockets, so nothing reaches the network.

**Test cases**
- Token checks: valid user; bad iss, expired, wrong key or missing scope → 401; the 401 header contents.
- M2M: listed vs unlisted client; M2M disabled; an M2M-only scope is not rejected with 403 at the route.
- Metadata fields.
- DCR: exact parameters and 201 body; non-loopback → 400; allowlist accepted; bad body → 400; LimitExceeded → 429.
- `/health` needs no auth.

**You run:** `uv run pytest -q`. It should be green and work offline.

## Step 3: OBO broker (Opus)
**`OboBroker.exchange(subject_token)`**
- Sends exactly the proven request: Basic OBO_ID:OBO_SECRET plus the five form fields, with a 10s timeout.
- Cache key is `(sha256(token), audience, scope)`. Entries live until `min(expires_in, jwt exp) − 60s`; nothing is cached if that is ≤ 0.
- Up to 1024 entries, with a lock per key so concurrent calls make one exchange.
- Errors raise `OboError`: `invalid_grant` → "re-authenticate / missing servicenow-api/access"; `invalid_client` → config error, logged only; 5xx/timeout → retryable.
- Tokens are never logged.

`auth_info(check_obo=true)` returns the decoded OBO claims.

**Tests**
- Exact request body and header.
- A cache hit makes no second request.
- Expiry triggers a re-exchange (injected clock).
- Keys are isolated per subject token.
- Concurrent calls make a single exchange.
- Error mapping.

**You run:**
- `~/obo-test.sh adele` as the baseline.
- `scripts/login.sh adele`, then call `auth_info {"check_obo":true}`. Expect `aud=servicenow-api`, `email=adelev@…` and `scope=servicenow-api/access`.
- Repeat the call and look for a cache hit in the log.
- Restart the server: the call still works without logging in again.
- With an M2M token: refused.

## Step 4: ServiceNow client and tools (Opus)
`servicenow.py` maps errors as follows:

| ServiceNow response | Message |
|---|---|
| 401 | "token rejected" |
| 403 | "ServiceNow ACL denied: <msg>" |
| 404, or an empty lookup | "not found or not visible to you" |
| 429/5xx | retryable |

Limits are clamped to 1..50.

Every tool does: `require_user()`, then `broker.exchange`, then the ServiceNow call. The tools are:
- `whoami`
- `incident_list(only_active, limit)`
- `incident_create`: `[via MCP agent]` prefix, `caller_id` taken from the whoami lookup, urgency 1..3
- `incident_add_work_note`: checks the number matches `^INC\d+$`, looks up the sys_id, then PATCHes
- `kb_search`: workflow_state=published; strips `^` and newlines from the query
- `kb_get_article`: number must match `^KB\d+$`
- `change_list`
- `change_create_normal`: Table API POST with type=normal, which the existing sn_obo_table scope already covers

**Tests:** error mapping; URLs, parameters and bodies for each tool; M2M refused on every user tool; a ServiceNow 403 comes back as an `isError` result with the ACL message.

**You run (Sonnet drives and records):**
- Inspector: log in as Adele → `whoami` returns Adele Vance.
- Claude Code: run `/mcp` and authenticate.
- Per persona:
  - `incident_list`: Adele 6+, Alex 3, Diego 1
  - `incident_create` as Adele: `sys_created_by` is AdeleV
  - `change_create_normal`: works for Megan; Adele gets ACL denied
  - `kb_search runbook`: Lidia sees Security Runbooks, Adele does not
- Restart the server mid-session: the next call works.
- M2M token: refused. Token from a foreign or tampered pool: 401.
- List and delete stale `dcr-*` clients.

## Finish (Sonnet)
- README: setup, env keys, run, verification runbook, limits.
- Update CLAUDE.md with the verified 4.1.4 facts and the M2M resources.

## Execution notes
- Steps run strictly in order. Each step ends with `uv run pytest -q` passing, then I pause for your real-world checks before starting the next one.
- No commits unless you ask. Secrets stay in `~/sn-obo.env` only.
