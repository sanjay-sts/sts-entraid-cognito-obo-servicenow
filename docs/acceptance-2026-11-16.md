# Acceptance record, 2026-11-16

## Environment

| Item | Value |
|---|---|
| Server | sn-obo-mcp, fastmcp 4.1.4, Python 3.13 |
| Client | MCP Inspector (browser), plus curl scripts |
| Cognito | pool `us-east-1_u9Q54aSvN` (ESSENTIALS) |
| ServiceNow | PDI `dev483791` (Brazil release) |

## Offline tests

`uv run pytest -q`: **55 passed in ~2.6 s** (network sockets blocked by `tests/conftest.py`).

| File | Tests |
|---|---|
| tests/test_auth.py | 7 |
| tests/test_oauth_routes.py | 16 |
| tests/test_obo.py | 15 |
| tests/test_tools.py | 17 |

<details><summary>Verbose pytest output</summary>

```
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.16.0, platformdirs-4.14.5, respx-0.23.1
collecting ... collected 55 items

tests/test_auth.py::test_no_token_401_with_challenge PASSED              [  1%]
tests/test_auth.py::test_user_token_accepted PASSED                      [  3%]
tests/test_auth.py::test_m2m_token_accepted_as_machine PASSED            [  5%]
tests/test_auth.py::test_m2m_unlisted_client_rejected PASSED             [  7%]
tests/test_auth.py::test_m2m_disabled_rejects_m2m_but_not_users PASSED   [  9%]
tests/test_auth.py::test_rejections PASSED                               [ 10%]
tests/test_auth.py::test_obo_client_credentials_token_is_machine PASSED  [ 12%]
tests/test_oauth_routes.py::test_health_no_auth PASSED                   [ 14%]
tests/test_oauth_routes.py::test_protected_resource_metadata PASSED      [ 16%]
tests/test_oauth_routes.py::test_as_metadata_facade PASSED               [ 18%]
tests/test_oauth_routes.py::test_register_happy_path PASSED              [ 20%]
tests/test_oauth_routes.py::test_register_sanitizes_name PASSED          [ 21%]
tests/test_oauth_routes.py::test_register_rejects_non_loopback PASSED    [ 23%]
tests/test_oauth_routes.py::test_register_allowlist PASSED               [ 25%]
tests/test_oauth_routes.py::test_register_bad_bodies PASSED              [ 27%]
tests/test_oauth_routes.py::test_register_rejects_confidential PASSED    [ 29%]
tests/test_oauth_routes.py::test_register_cognito_errors PASSED          [ 30%]
tests/test_oauth_routes.py::test_cors_preflight_for_browser_clients PASSED [ 32%]
tests/test_oauth_routes.py::test_cors_exposes_www_authenticate PASSED    [ 34%]
tests/test_oauth_routes.py::test_authorize_strips_resource_and_redirects PASSED [ 36%]
tests/test_oauth_routes.py::test_authorize_prompt_configurable PASSED    [ 38%]
tests/test_oauth_routes.py::test_token_passthrough_strips_resource PASSED [ 40%]
tests/test_oauth_routes.py::test_token_passthrough_network_error PASSED  [ 41%]
tests/test_obo.py::test_exact_request PASSED                             [ 43%]
tests/test_obo.py::test_cache_hit_and_isolation PASSED                   [ 45%]
tests/test_obo.py::test_expiry_triggers_reexchange PASSED                [ 47%]
tests/test_obo.py::test_short_lived_not_cached PASSED                    [ 49%]
tests/test_obo.py::test_jwt_exp_caps_expires_in PASSED                   [ 50%]
tests/test_obo.py::test_concurrent_single_exchange PASSED                [ 52%]
tests/test_obo.py::test_error_mapping[400-body0-re-authenticate] PASSED  [ 54%]
tests/test_obo.py::test_error_mapping[400-body1-configuration error] PASSED [ 56%]
tests/test_obo.py::test_error_mapping[500-body2-temporarily unavailable] PASSED [ 58%]
tests/test_obo.py::test_error_mapping[429-body3-temporarily unavailable] PASSED [ 60%]
tests/test_obo.py::test_error_mapping[400-body4-400 weird] PASSED        [ 61%]
tests/test_obo.py::test_network_error PASSED                             [ 63%]
tests/test_obo.py::test_auth_info_check_obo_user PASSED                  [ 65%]
tests/test_obo.py::test_auth_info_check_obo_refuses_m2m PASSED           [ 67%]
tests/test_obo.py::test_auth_info_obo_error_surfaces PASSED              [ 69%]
tests/test_tools.py::test_whoami_uses_obo_bearer PASSED                  [ 70%]
tests/test_tools.py::test_incident_list PASSED                           [ 72%]
tests/test_tools.py::test_incident_list_limit_validated PASSED           [ 74%]
tests/test_tools.py::test_incident_create PASSED                         [ 76%]
tests/test_tools.py::test_add_work_note PASSED                           [ 78%]
tests/test_tools.py::test_add_work_note_not_visible_and_invalid PASSED   [ 80%]
tests/test_tools.py::test_add_work_note_acl_denied PASSED                [ 81%]
tests/test_tools.py::test_kb_search_and_get PASSED                       [ 83%]
tests/test_tools.py::test_kb_get_not_visible PASSED                      [ 85%]
tests/test_tools.py::test_change_list_and_create PASSED                  [ 87%]
tests/test_tools.py::test_change_create_denied PASSED                    [ 89%]
tests/test_tools.py::test_error_mapping[401-rejected the token] PASSED   [ 90%]
tests/test_tools.py::test_error_mapping[404-not visible] PASSED          [ 92%]
tests/test_tools.py::test_error_mapping[503-temporarily unavailable] PASSED [ 94%]
tests/test_tools.py::test_error_mapping[400-failed (400)] PASSED         [ 96%]
tests/test_tools.py::test_m2m_refused_on_all_user_tools PASSED           [ 98%]
tests/test_tools.py::test_tools_listed PASSED                            [100%]

============================== 55 passed in 2.58s ==============================
```

</details>

## Live results

| Check | Expected | Actual | Status |
|---|---|---|---|
| Cognito pool sanity | resource server servicenow-api, JWKS present | resource servers = [servicenow-api]; JWKS keys = 2 | PASS |
| DCR via curl | `/register` creates a public Cognito client | Created `dcr-curl-test`: flows [code], scopes [email, openid, profile, servicenow-api/access], callback http://localhost:6274/oauth/callback, IdP [EntraID]; deleted afterwards | PASS |
| Non-loopback redirect | rejected | `https://evil.example/cb` -> 400 `invalid_redirect_uri` | PASS |
| 127.0.0.1 callback | accepted by Cognito | accepted (risk retired) | PASS |
| `scripts/login.sh adele` + `auth_info` via curl | kind=user, scope includes servicenow-api/access; tampered token rejected | kind=user, scopes include servicenow-api/access; tampered token -> 401 | PASS |
| Unauthenticated `/mcp` | 401 with challenge | 401, `WWW-Authenticate` has `scope="servicenow-api/access"` and `resource_metadata` | PASS |
| OBO exchange (`auth_info check_obo`) | aud=servicenow-api, email claim, scope | aud=servicenow-api, email=adelev@2tdgcb.onmicrosoft.com (lowercase, from pre-token Lambda), scope=servicenow-api/access, client_id=mcp-obo (njs5uq6vuorsagsb3meb8cn3f) | PASS |
| MCP Inspector first attempt | login succeeds | Cognito error `invalid_target: custom scopes requested for resource-binding must be assigned to the resource being requested` | FAIL, then FIXED |
| Fix for the above | `resource` no longer reaches Cognito | `/authorize` + `/token` pass-throughs added. Verified: direct Cognito with `resource` -> invalid_target; via `/authorize` -> 302 to login.microsoftonline.com. A CORS preflight 405 was also found and fixed before Inspector testing | PASS |
| Inspector DCR + PKCE end to end (acceptance #1) | tools usable after login | Log: 401 -> PRM -> AS metadata -> POST /register 201 (client "MCP Inspector", redirect http://127.0.0.1:6274/oauth/callback) -> /authorize 302 -> /token 200 -> /mcp 200. Inspector requests only scope servicenow-api/access (no openid); accepted by Cognito | PASS |
| User switching | login as a different user | Auto-login as previous user blocked switching; fixed by `prompt=login` (`AUTHORIZE_PROMPT`) | PASS after fix |
| Adele `whoami` | Adele Vance | Adele Vance (AdeleV@2tdgcb.onmicrosoft.com) | PASS |
| OBO cache | second call reuses token | second call logs `obo cache hit` | PASS |
| Alex `whoami`, `incident_list` [LAB] | Alex Wilber; 3 incidents | Alex Wilber; 3 (INC0010001-0003, SG-SN-Network) | PASS |
| Adele `incident_list` (only_active=false, contains=[LAB], limit=50) | >= 6 | 8 (6 seeded INC0010001-0006 + INC0010007 from earlier lab + INC0010008 created via MCP) | PASS |
| Adele `incident_create` | created as Adele | INC0010009, caller_id=Adele Vance, sys_created_by=AdeleV@2tdgcb.onmicrosoft.com, prefix "[via MCP agent]" | PASS |
| Adele `change_create_normal` | ACL denied | "ServiceNow ACL denied: Operation Failed - ACL Exception Insert Failed due to security constraints" (SN 403) | PASS |
| Megan `change_create_normal` | created | CHG0030007, type Normal, sys_created_by=MeganB@2tdgcb.onmicrosoft.com | PASS |
| Diego `incident_list` [LAB] | 1 | 1 (INC0010006) | PASS |
| Adele `kb_search` | none visible | 0; instance has only 2 published articles (KB0010001, KB0010002), both in Security Runbooks | PASS |
| Stateless restart mid-session (acceptance #4) | next call works without re-login | Server restarted during Alex's session; next `whoami` worked (JWKS re-fetched, fresh exchange) | PASS |
| Table API scope covers `kb_knowledge`, `change_request` | 200, no unscoped-API 403 | 200 for both | PASS |
| **Lidia `kb_search`** | Security Runbooks articles | **0 results** | **GAP (open)** |

Not executed:

- Claude Code client (acceptance #2).
- M2M token tests (acceptance #5, M2M part); `mcp-m2m` resource server not created yet.
- Diego work note on INC0010001 (expected: not visible).

## Known gap: Lidia / Security Runbooks via Table API

Evidence:

- Lidia's OBO token is correct: email `lidiah@2tdgcb.onmicrosoft.com`, ServiceNow user Lidia Holloway; she sees 1 [LAB] incident (INC0010003) via `~/obo-test.sh`.
- `kb_knowledge_base` via Table API returns [Security Runbooks, Knowledge] (both active). So token, auth scope and Table API all work.
- `kb_knowledge` via Table API returns `[]` even with **no filter**. This is row-level filtering inside ServiceNow, not the MCP tool's `workflow_state=published` filter.
- Both articles are Published: KB0010001 "[LAB] VPN compromise response runbook", KB0010002 "[LAB] Phishing triage runbook".
- Lidia is a member of SG-SN-Security, which is the Can Read user-criteria group on the Security Runbooks KB.
- Impersonating Lidia in the UI, KB0010001 is readable.

Conclusion: a difference between the UI session and the REST/token session inside ServiceNow. No MCP server change is needed.

Next diagnostic steps:

1. Before-query business rules on `kb_knowledge` (`sys_script.list`, Table=kb_knowledge, When=before, Query=true).
2. System Security -> Access Analyzer: Lidia, `kb_knowledge`, KB0010001, read.
3. REST API Access Policies, and any table restrictions on the inbound integration auth scope.
4. Lidia's roles (check `snc_internal` under Explicit Roles) and her Valid to date.
5. Flush the user-criteria cache (`cache.do`) and retry.

## Other open items

- M2M setup (see [runbook](runbook.md)) and M2M tests.
- Claude Code client test.
- Clean up stale `dcr-*` Cognito clients (several Inspector clients were created during testing).
