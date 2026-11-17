from conftest import ISS, M2M_ID, MCP_HEADERS, call_tool, make_settings

import pytest as _pytest

pytestmark = _pytest.mark.anyio


async def test_no_token_401_with_challenge(client):
    r = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers=MCP_HEADERS)
    assert r.status_code == 401
    www = r.headers["www-authenticate"]
    assert 'scope="servicenow-api/access"' in www
    assert 'resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource/mcp"' in www


async def test_user_token_accepted(client, mint):
    status, result = await call_tool(client, "auth_info", token=mint("user"))
    assert status == 200 and not result["isError"]
    info = result["structuredContent"]
    assert info["kind"] == "user"
    assert info["client_id"] == "dcrclient1"  # original, not MultiAuth-qualified
    assert info["username"] == "EntraID_adelev"


async def test_m2m_token_accepted_as_machine(client, mint):
    status, result = await call_tool(client, "auth_info", token=mint("m2m"))
    assert status == 200
    info = result["structuredContent"]
    assert info["kind"] == "machine" and info["client_id"] == M2M_ID
    assert info["scopes"] == ["mcp-m2m/invoke"]  # not 403'd by a route-level user-scope gate


async def test_m2m_unlisted_client_rejected(client, mint):
    status, _ = await call_tool(client, "auth_info", token=mint("m2m", client_id="someoneelse"))
    assert status == 401


async def test_m2m_disabled_rejects_m2m_but_not_users(make_client, mint):
    async with make_client(make_settings(m2m_client_ids=())) as c:
        assert (await call_tool(c, "auth_info", token=mint("m2m")))[0] == 401
        assert (await call_tool(c, "auth_info", token=mint("user")))[0] == 200


async def test_rejections(client, mint, other_keypair):
    bad = {
        "wrong issuer": mint("user", issuer=ISS.replace("TESTPOOL", "OTHERPOOL")),
        "expired": mint("user", expires_in=-60),
        "wrong key": mint("user", key=other_keypair),
        "missing user scope": mint("user", scopes=["openid", "email"]),
        "tampered": mint("user")[:-4] + "AAAA",
    }
    for label, token in bad.items():
        status, _ = await call_tool(client, "auth_info", token=token)
        assert status == 401, label


async def test_obo_client_credentials_token_is_machine(client, mint):
    """A pool token with the user scope but no username (e.g. client_credentials) is not a user."""
    tok = mint("user", username=None, scopes=["servicenow-api/access"])
    status, result = await call_tool(client, "auth_info", token=tok)
    assert status == 200 and result["structuredContent"]["kind"] == "machine"
