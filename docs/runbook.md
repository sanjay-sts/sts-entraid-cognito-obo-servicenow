# Runbook

Operational how-tos for the lab. Assumes `~/sn-obo.env` exists and `AWS_PROFILE=admin` (SSO).

## Start / stop

```bash
aws sso login --profile admin        # if the SSO token expired
uv sync
uv run python server.py              # Ctrl-C to stop; logs to stdout
curl -s localhost:8000/health        # {"status":"ok","m2m_enabled":false}
```

Restarting is safe at any time: the server holds no sessions; the next tool call re-fetches JWKS and re-exchanges the token.

## Test in MCP Inspector

1. Start Inspector, transport **Streamable HTTP**, URL `http://localhost:8000/mcp`, connection type Direct or Via Proxy.
2. Leave **client ID empty** (the server's `/register` creates a Cognito public client).
3. Open Auth Settings, run the OAuth flow, sign in with Entra, then list tools and call `whoami` or `auth_info`.

The log should show: 401, protected-resource metadata, AS metadata, `POST /register` 201, `/authorize` 302, `/token` 200, `/mcp` 200.

### Switch users

Auth Settings -> **Clear OAuth State** -> Connect -> choose "Use another account" at Entra. The server adds `prompt=login` to `/authorize` (`AUTHORIZE_PROMPT`), so Entra always asks. Use a private window if the browser still auto-signs-in.

## Curl path (no MCP client)

```bash
scripts/login.sh adele                      # open printed URL in a private window, paste the code
scripts/call.sh adele whoami
scripts/call.sh adele incident_list '{"only_active":false,"contains":"[LAB]","limit":50}'
scripts/call.sh adele auth_info '{"check_obo":true}'
```

Tokens are saved in `~/.cache/sn-obo/<label>.at`. `login.sh` uses the pre-registered `gate1-test` client (`GATE1_ID`, callback `http://localhost:6274/oauth/callback`). Set `BASE_URL` if the server is not on localhost:8000.

## Stale DCR clients

Every Inspector connection can create a `dcr-*` public client; there is no automatic cleanup.

```bash
aws cognito-idp list-user-pool-clients --user-pool-id "$POOL_ID" --max-results 60 \
  --profile admin --region us-east-1 \
  --query "UserPoolClients[?starts_with(ClientName,'dcr-')].[ClientId,ClientName]" --output text

aws cognito-idp delete-user-pool-client --user-pool-id "$POOL_ID" --client-id <ClientId> \
  --profile admin --region us-east-1
```

Deleting a client invalidates its refresh tokens; the MCP client will re-register on its next connect.

## M2M setup (NOT YET EXECUTED)

```bash
aws cognito-idp create-resource-server --user-pool-id "$POOL_ID" \
  --identifier mcp-m2m --name mcp-m2m --scopes ScopeName=invoke,ScopeDescription="Invoke MCP as machine"

aws cognito-idp create-user-pool-client --user-pool-id "$POOL_ID" --client-name mcp-m2m-test \
  --generate-secret --allowed-o-auth-flows client_credentials \
  --allowed-o-auth-scopes mcp-m2m/invoke --allowed-o-auth-flows-user-pool-client \
  --supported-identity-providers COGNITO

# put the returned ClientId in ~/sn-obo.env as M2M_CLIENT_IDS=<id> and restart the server
curl -s -u "<ClientId>:<ClientSecret>" -d grant_type=client_credentials -d scope=mcp-m2m/invoke \
  "$COG_URL/oauth2/token"
```

Expected: `auth_info` shows `kind=machine`; user tools refuse. Save the token as `~/.cache/sn-obo/m2m.at` to use `scripts/call.sh m2m auth_info`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Cognito `invalid_target: custom scopes requested for resource-binding must be assigned to the resource being requested` | Cognito honours RFC 8707 `resource`; our scope belongs to `servicenow-api` | Handled by `/authorize` and `/token` (they drop `resource`). If still seen, the client is using cached metadata that points straight at Cognito: Clear OAuth State and close ALL private windows. Server log will show no `/.well-known` or `/authorize` requests |
| Signed in as the previous user automatically | Entra SSO session | `prompt=login` is forced by default; check `AUTHORIZE_PROMPT` is not empty; use a fresh private window |
| Browser `405` on OPTIONS (CORS preflight) | Missing CORS | Fixed by loopback CORS middleware in `server.py`; origin must be localhost/127.0.0.1 |
| `address already in use` on port 8000 | Old server running | `ss -ltnp \| grep :8000`, stop that process or set `PORT` |
| `/register` 500 or AWS errors | SSO token expired | `aws sso login --profile admin` |
| Pasted text shows `^[[200~` in terminal prompts | Bracketed-paste glitch | Paste again, or type the value; for `login.sh` paste only the code |
| `invalid_grant` on exchange ("re-authenticate") | Login token lacked `servicenow-api/access`, or expired | Re-login; clients must request that scope |
| ServiceNow 403 `Access to unscoped api is not allowed` | Inbound integration auth scope does not list the API | Add the API (Table API, or others you use) to the `sn_obo_table` auth scope |
| `ServiceNow ACL denied: ...` | The user lacks rights (expected for e.g. Adele on `change_create_normal`) | Verify with a user holding the role (Megan) |
| `Not found or not visible to you.` | Row hidden by ACL/user criteria or absent | Check as another user; see Lidia gap in the acceptance record |
| `401 ServiceNow rejected the token` | OBO token lacks `email` claim or no matching SN user | Check pre-token Lambda and `auth_info check_obo` output (`email` lowercase) |
