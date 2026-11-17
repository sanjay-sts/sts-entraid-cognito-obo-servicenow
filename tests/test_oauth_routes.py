from botocore.stub import ANY

from conftest import BASE, POOL, make_settings

import pytest as _pytest

pytestmark = _pytest.mark.anyio

LOGIN_SCOPES = ["openid", "email", "profile", "servicenow-api/access"]


async def test_health_no_auth(client):
    r = await client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok", "m2m_enabled": True}


async def test_protected_resource_metadata(client):
    r = await client.get("/.well-known/oauth-protected-resource/mcp")
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == f"{BASE}/mcp"
    assert body["authorization_servers"] == [BASE]
    assert body["scopes_supported"] == ["servicenow-api/access"]


async def test_as_metadata_facade(client, settings):
    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        m = (await client.get(path)).json()
        assert m["issuer"] == BASE
        assert m["authorization_endpoint"] == f"{BASE}/authorize"
        assert m["token_endpoint"] == f"{BASE}/token"
        assert m["revocation_endpoint"] == f"{settings.cog_url}/oauth2/revoke"
        assert m["registration_endpoint"] == f"{BASE}/register"
        assert m["code_challenge_methods_supported"] == ["S256"]
        assert m["token_endpoint_auth_methods_supported"] == ["none"]
        assert m["scopes_supported"] == LOGIN_SCOPES


def _expected_params(redirects, name="dcr-Claude Code"):
    return {
        "UserPoolId": POOL, "ClientName": name, "GenerateSecret": False,
        "AllowedOAuthFlowsUserPoolClient": True, "AllowedOAuthFlows": ["code"],
        "AllowedOAuthScopes": LOGIN_SCOPES, "SupportedIdentityProviders": ["EntraID"],
        "CallbackURLs": redirects, "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
        "RefreshTokenValidity": 30, "AccessTokenValidity": 60, "IdTokenValidity": 60,
        "TokenValidityUnits": {"RefreshToken": "days", "AccessToken": "minutes", "IdToken": "minutes"},
        "EnableTokenRevocation": True, "PreventUserExistenceErrors": "ENABLED",
    }


def _create_response(client_id="newclient123"):
    return {"UserPoolClient": {"UserPoolId": POOL, "ClientName": "dcr-x", "ClientId": client_id}}


async def test_register_happy_path(client, cognito_stub):
    _, stub = cognito_stub
    redirects = ["http://localhost:6274/oauth/callback", "http://127.0.0.1:33418/callback"]
    stub.add_response("create_user_pool_client", _create_response(), _expected_params(redirects))
    r = await client.post("/register", json={"client_name": "Claude Code", "redirect_uris": redirects,
                                             "grant_types": ["authorization_code", "refresh_token"]})
    assert r.status_code == 201
    body = r.json()
    assert body["client_id"] == "newclient123"
    assert body["redirect_uris"] == redirects
    assert body["token_endpoint_auth_method"] == "none"
    assert body["response_types"] == ["code"]
    assert "client_secret" not in body
    assert body["scope"] == " ".join(LOGIN_SCOPES)


async def test_register_sanitizes_name(client, cognito_stub):
    _, stub = cognito_stub
    params = _expected_params(["http://localhost:1/cb"], name=ANY)
    stub.add_response("create_user_pool_client", _create_response(), params)
    r = await client.post("/register", json={"client_name": "evil<script>/name", "redirect_uris": ["http://localhost:1/cb"]})
    assert r.status_code == 201


async def test_register_rejects_non_loopback(client):
    for uri in ["https://evil.example/cb", "http://evil.example/cb", "http://localhost.evil.com/cb",
                "http://user@localhost/cb", "javascript:alert(1)"]:
        r = await client.post("/register", json={"redirect_uris": [uri]})
        assert r.status_code == 400, uri
        assert r.json()["error"] == "invalid_redirect_uri"


async def test_register_allowlist(make_client, cognito_stub):
    _, stub = cognito_stub
    uri = "https://agent.example.com/oauth/callback"
    stub.add_response("create_user_pool_client", _create_response(), _expected_params([uri], name=ANY))
    async with make_client(make_settings(dcr_redirect_allowlist=(uri,))) as c:
        r = await c.post("/register", json={"redirect_uris": [uri]})
        assert r.status_code == 201


async def test_register_bad_bodies(client):
    for body in [b"not json", b"[]", b"{}", b'{"redirect_uris": []}', b'{"redirect_uris": "http://localhost/cb"}']:
        r = await client.post("/register", content=body, headers={"Content-Type": "application/json"})
        assert r.status_code == 400, body


async def test_register_rejects_confidential(client):
    r = await client.post("/register", json={"redirect_uris": ["http://localhost/cb"],
                                             "token_endpoint_auth_method": "client_secret_basic"})
    assert r.status_code == 400


async def test_register_cognito_errors(client, cognito_stub):
    _, stub = cognito_stub
    stub.add_client_error("create_user_pool_client", "LimitExceededException", "too many")
    stub.add_client_error("create_user_pool_client", "InvalidParameterException", "bad callback")
    stub.add_client_error("create_user_pool_client", "InternalErrorException", "secret aws detail")
    body = {"redirect_uris": ["http://localhost/cb"]}
    assert (await client.post("/register", json=body)).status_code == 429
    assert (await client.post("/register", json=body)).status_code == 400
    r = await client.post("/register", json=body)
    assert r.status_code == 500 and "secret aws detail" not in r.text


async def test_cors_preflight_for_browser_clients(client):
    hdrs = {"Origin": "http://localhost:6274", "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,authorization,mcp-protocol-version"}
    for path in ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server",
                 "/register", "/mcp"]:
        r = await client.options(path, headers=hdrs)
        assert r.status_code == 200, path
        assert r.headers["access-control-allow-origin"] == "http://localhost:6274"
    r = await client.options("/register", headers={**hdrs, "Origin": "https://evil.example"})
    assert r.status_code == 400


async def test_cors_exposes_www_authenticate(client):
    r = await client.post("/mcp", json={}, headers={"Origin": "http://localhost:6274"})
    assert r.status_code == 401
    assert "www-authenticate" in r.headers["access-control-expose-headers"].lower()


async def test_authorize_strips_resource_and_redirects(client, settings):
    from urllib.parse import parse_qs, urlsplit
    r = await client.get("/authorize", params={
        "response_type": "code", "client_id": "c1", "redirect_uri": "http://localhost:6274/oauth/callback",
        "scope": "servicenow-api/access", "state": "s", "code_challenge": "x", "code_challenge_method": "S256",
        "resource": "http://localhost:8000/mcp"}, follow_redirects=False)
    assert r.status_code == 302
    loc = urlsplit(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{settings.cog_url}/oauth2/authorize"
    q = {k: v[0] for k, v in parse_qs(loc.query).items()}
    assert "resource" not in q
    assert q["client_id"] == "c1" and q["code_challenge_method"] == "S256" and q["state"] == "s"
    assert q["identity_provider"] == "EntraID"
    assert q["prompt"] == "login"


async def test_authorize_prompt_configurable(make_client, client):
    from urllib.parse import parse_qs, urlsplit
    r = await client.get("/authorize", params={"client_id": "c", "prompt": "none"}, follow_redirects=False)
    assert parse_qs(urlsplit(r.headers["location"]).query)["prompt"] == ["none"]  # client's value wins
    async with make_client(make_settings(authorize_prompt="")) as c:
        r = await c.get("/authorize", params={"client_id": "c"}, follow_redirects=False)
        assert "prompt" not in parse_qs(urlsplit(r.headers["location"]).query)


async def test_token_passthrough_strips_resource(client, settings):
    import httpx
    import respx
    from urllib.parse import parse_qs
    with respx.mock:
        route = respx.post(f"{settings.cog_url}/oauth2/token").mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant"}))
        r = await client.post("/token", data={"grant_type": "authorization_code", "code": "abc",
                                              "client_id": "c1", "code_verifier": "v",
                                              "redirect_uri": "http://localhost:6274/oauth/callback",
                                              "resource": "http://localhost:8000/mcp"},
                              headers={"Authorization": "Basic Zm9vOmJhcg=="})
        assert r.status_code == 400 and r.json() == {"error": "invalid_grant"}  # Cognito status/body passed through
        assert r.headers["cache-control"] == "no-store"
        req = route.calls[0].request
        sent = parse_qs(req.content.decode())
        assert "resource" not in sent and sent["code"] == ["abc"] and sent["code_verifier"] == ["v"]
        assert req.headers["authorization"] == "Basic Zm9vOmJhcg=="


async def test_token_passthrough_network_error(client, settings):
    import httpx
    import respx
    with respx.mock:
        respx.post(f"{settings.cog_url}/oauth2/token").mock(side_effect=httpx.ConnectError("x"))
        r = await client.post("/token", data={"grant_type": "refresh_token", "refresh_token": "r"})
        assert r.status_code == 502
