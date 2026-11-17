import time
from urllib.parse import parse_qs

import anyio
import httpx
import pytest
import respx

from conftest import call_tool
from sn_obo_mcp.obo import OboBroker, OboError

import pytest as _pytest

pytestmark = _pytest.mark.anyio

TOKEN_URL = "https://test-domain.auth.us-east-1.amazoncognito.com/oauth2/token"


@pytest.fixture
def obo_token(keypair):
    def _make(expires_in=3600, email="adelev@example.com"):
        return keypair.create_token(
            subject="user-sub-1", issuer="https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TESTPOOL",
            scopes=["servicenow-api/access"], expires_in_seconds=expires_in,
            additional_claims={"aud": "servicenow-api", "email": email, "username": "EntraID_adelev",
                               "client_id": "oboclient", "token_use": "access"})
    return _make


def ok(token, expires_in=3600):
    return httpx.Response(200, json={"access_token": token, "expires_in": expires_in, "token_type": "Bearer"})


@respx.mock
async def test_exact_request(settings, obo_token):
    route = respx.post(TOKEN_URL).mock(return_value=ok(obo_token()))
    tok = await OboBroker(settings).exchange("subject.jwt.token")
    assert tok == route.calls[0].response.json()["access_token"]
    req = route.calls[0].request
    assert req.headers["authorization"] == "Basic " + __import__("base64").b64encode(b"oboclient:obosecret").decode()
    assert parse_qs(req.content.decode()) == {
        "grant_type": ["urn:ietf:params:oauth:grant-type:token-exchange"],
        "subject_token": ["subject.jwt.token"],
        "subject_token_type": ["urn:ietf:params:oauth:token-type:access_token"],
        "audience": ["servicenow-api"],
        "scope": ["servicenow-api/access"],
    }


@respx.mock
async def test_cache_hit_and_isolation(settings, obo_token):
    route = respx.post(TOKEN_URL).mock(return_value=ok(obo_token()))
    b = OboBroker(settings)
    t1 = await b.exchange("subject-A")
    assert await b.exchange("subject-A") == t1
    assert route.call_count == 1
    await b.exchange("subject-B")
    assert route.call_count == 2


@respx.mock
async def test_expiry_triggers_reexchange(settings, obo_token):
    route = respx.post(TOKEN_URL).mock(return_value=ok(obo_token(expires_in=600), expires_in=600))
    now = [time.time()]
    b = OboBroker(settings, clock=lambda: now[0])
    await b.exchange("s")
    now[0] += 500  # within 600-60
    await b.exchange("s")
    assert route.call_count == 1
    now[0] += 60  # past exp-60
    await b.exchange("s")
    assert route.call_count == 2


@respx.mock
async def test_short_lived_not_cached(settings, obo_token):
    route = respx.post(TOKEN_URL).mock(return_value=ok(obo_token(expires_in=30), expires_in=30))
    b = OboBroker(settings)
    await b.exchange("s")
    await b.exchange("s")
    assert route.call_count == 2


@respx.mock
async def test_jwt_exp_caps_expires_in(settings, obo_token):
    # expires_in claims 3600 but the token itself expires in 50s -> not cacheable
    route = respx.post(TOKEN_URL).mock(return_value=ok(obo_token(expires_in=50), expires_in=3600))
    b = OboBroker(settings)
    await b.exchange("s")
    await b.exchange("s")
    assert route.call_count == 2


@respx.mock
async def test_concurrent_single_exchange(settings, obo_token):
    async def slow(request):
        await anyio.sleep(0.05)
        return ok(obo_token())

    route = respx.post(TOKEN_URL).mock(side_effect=slow)
    b = OboBroker(settings)
    results = []

    async def one():
        results.append(await b.exchange("same"))

    async with anyio.create_task_group() as tg:
        for _ in range(5):
            tg.start_soon(one)
    assert route.call_count == 1 and len(set(results)) == 1


@pytest.mark.parametrize("status,body,fragment", [
    (400, {"error": "invalid_grant"}, "re-authenticate"),
    (400, {"error": "invalid_client"}, "configuration error"),
    (500, {}, "temporarily unavailable"),
    (429, {"error": "too_many"}, "temporarily unavailable"),
    (400, {"error": "weird"}, "400 weird"),
])
async def test_error_mapping(settings, status, body, fragment):
    with respx.mock:
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(status, json=body))
        with pytest.raises(OboError, match=fragment):
            await OboBroker(settings).exchange("s")


@respx.mock
async def test_network_error(settings):
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(OboError, match="network"):
        await OboBroker(settings).exchange("s")


# --- through the MCP endpoint ------------------------------------------------

@respx.mock
async def test_auth_info_check_obo_user(client, mint, obo_token):
    respx.post(TOKEN_URL).mock(return_value=ok(obo_token()))
    status, result = await call_tool(client, "auth_info", {"check_obo": True}, token=mint("user"))
    assert status == 200 and not result["isError"]
    obo = result["structuredContent"]["obo"]
    assert obo["aud"] == "servicenow-api" and obo["email"] == "adelev@example.com"
    assert obo["scope"] == "servicenow-api/access"


@respx.mock
async def test_auth_info_check_obo_refuses_m2m(client, mint):
    route = respx.post(TOKEN_URL)
    status, result = await call_tool(client, "auth_info", {"check_obo": True}, token=mint("m2m"))
    assert status == 200 and result["isError"]
    assert "machine" in result["content"][0]["text"].lower()
    assert route.call_count == 0


@respx.mock
async def test_auth_info_obo_error_surfaces(client, mint):
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(400, json={"error": "invalid_grant"}))
    status, result = await call_tool(client, "auth_info", {"check_obo": True}, token=mint("user"))
    assert status == 200 and result["isError"]
    assert "re-authenticate" in result["content"][0]["text"]
