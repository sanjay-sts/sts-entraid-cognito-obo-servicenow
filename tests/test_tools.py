import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx

from conftest import call_tool

pytestmark = pytest.mark.anyio

TOKEN_URL = "https://test-domain.auth.us-east-1.amazoncognito.com/oauth2/token"
SN = "https://sn.example.com"
ME = {"sys_id": "u123", "name": "Adele Vance", "user_name": "AdeleV", "email": "adelev@example.com"}


@pytest.fixture
def sn(keypair):
    """respx router with a working token exchange; returns (router, obo_token)."""
    obo = keypair.create_token(subject="user-sub-1", issuer="x", scopes=["servicenow-api/access"],
                               additional_claims={"aud": "servicenow-api", "email": "adelev@example.com"})
    with respx.mock(assert_all_called=False) as router:
        router.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": obo, "expires_in": 3600}))
        router.get(f"{SN}/api/now/table/sys_user").mock(return_value=httpx.Response(200, json={"result": [ME]}))
        yield router, obo


def q(request) -> dict:
    return {k: v[0] for k, v in parse_qs(urlsplit(str(request.url)).query).items()}


async def ok_call(client, token, name, args=None):
    status, result = await call_tool(client, name, args, token=token)
    assert status == 200, status
    assert not result["isError"], result["content"][0]["text"]
    return result["structuredContent"]


async def err_call(client, token, name, args=None) -> str:
    status, result = await call_tool(client, name, args, token=token)
    assert status == 200 and result["isError"]
    return result["content"][0]["text"]


async def test_whoami_uses_obo_bearer(client, mint, sn):
    router, obo = sn
    out = await ok_call(client, mint("user"), "whoami")
    assert out["servicenow_user"]["name"] == "Adele Vance"
    assert out["obo_token"]["aud"] == "servicenow-api"
    req = router.routes[1].calls[0].request
    assert req.headers["authorization"] == f"Bearer {obo}"
    assert q(req)["sysparm_query"] == "sys_id=javascript:gs.getUserID()"


async def test_incident_list(client, mint, sn):
    router, _ = sn
    route = router.get(f"{SN}/api/now/table/incident").mock(
        return_value=httpx.Response(200, json={"result": [{"number": "INC0010001"}]}))
    out = await ok_call(client, mint("user"), "incident_list", {"limit": 5, "contains": "[LAB]^ORactive=false"})
    assert out["count"] == 1
    params = q(route.calls[0].request)
    assert params["sysparm_limit"] == "5"
    # '^' stripped from user text: no injected OR condition
    assert params["sysparm_query"] == "active=true^short_descriptionLIKE[LAB] ORactive=false^ORDERBYDESCsys_created_on"


async def test_incident_list_limit_validated(client, mint, sn):
    await err_call(client, mint("user"), "incident_list", {"limit": 500})


async def test_incident_create(client, mint, sn):
    router, _ = sn
    route = router.post(f"{SN}/api/now/table/incident").mock(
        return_value=httpx.Response(201, json={"result": {"number": "INC0010099", "sys_created_by": "AdeleV"}}))
    out = await ok_call(client, mint("user"), "incident_create",
                        {"short_description": "Printer on fire", "description": "d", "urgency": 2})
    assert out["created"]["number"] == "INC0010099"
    body = json.loads(route.calls[0].request.content)
    assert body == {"short_description": "[via MCP agent] Printer on fire", "description": "d",
                    "urgency": "2", "caller_id": "u123"}


async def test_add_work_note(client, mint, sn):
    router, _ = sn
    router.get(f"{SN}/api/now/table/incident").mock(
        return_value=httpx.Response(200, json={"result": [{"sys_id": "abc", "number": "INC0010001"}]}))
    patch = router.patch(f"{SN}/api/now/table/incident/abc").mock(
        return_value=httpx.Response(200, json={"result": {"number": "INC0010001"}}))
    await ok_call(client, mint("user"), "incident_add_work_note", {"number": "inc0010001", "note": "hello"})
    assert json.loads(patch.calls[0].request.content) == {"work_notes": "[via MCP agent] hello"}


async def test_add_work_note_not_visible_and_invalid(client, mint, sn):
    router, _ = sn
    router.get(f"{SN}/api/now/table/incident").mock(return_value=httpx.Response(200, json={"result": []}))
    assert "not visible" in await err_call(client, mint("user"), "incident_add_work_note",
                                           {"number": "INC0010001", "note": "x"})
    assert "Invalid incident" in await err_call(client, mint("user"), "incident_add_work_note",
                                                {"number": "INC1^ORx", "note": "x"})


async def test_add_work_note_acl_denied(client, mint, sn):
    router, _ = sn
    router.get(f"{SN}/api/now/table/incident").mock(
        return_value=httpx.Response(200, json={"result": [{"sys_id": "abc", "number": "INC0010001"}]}))
    router.patch(f"{SN}/api/now/table/incident/abc").mock(return_value=httpx.Response(
        403, json={"error": {"message": "Operation Failed", "detail": "ACL Exception Update Failed"}}))
    msg = await err_call(client, mint("user"), "incident_add_work_note", {"number": "INC0010001", "note": "x"})
    assert msg.startswith("ServiceNow ACL denied") and "ACL Exception" in msg


async def test_kb_search_and_get(client, mint, sn):
    router, _ = sn
    route = router.get(f"{SN}/api/now/table/kb_knowledge").mock(
        return_value=httpx.Response(200, json={"result": [{"number": "KB0010001", "text": "<p>hi</p>"}]}))
    out = await ok_call(client, mint("user"), "kb_search", {"query": "vpn^ORnumber=x"})
    assert out["count"] == 1
    assert q(route.calls[0].request)["sysparm_query"] == (
        "workflow_state=published^short_descriptionLIKEvpn ORnumber=x^ORtextLIKEvpn ORnumber=x^ORDERBYnumber")
    art = await ok_call(client, mint("user"), "kb_get_article", {"number": "KB0010001"})
    assert art["number"] == "KB0010001"
    assert q(route.calls[1].request)["sysparm_query"] == "number=KB0010001^workflow_state=published"


async def test_kb_get_not_visible(client, mint, sn):
    router, _ = sn
    router.get(f"{SN}/api/now/table/kb_knowledge").mock(return_value=httpx.Response(200, json={"result": []}))
    assert "not visible" in await err_call(client, mint("user"), "kb_get_article", {"number": "KB0099999"})


async def test_change_list_and_create(client, mint, sn):
    router, _ = sn
    router.get(f"{SN}/api/now/table/change_request").mock(
        return_value=httpx.Response(200, json={"result": [{"number": "CHG0030001"}]}))
    post = router.post(f"{SN}/api/now/table/change_request").mock(
        return_value=httpx.Response(201, json={"result": {"number": "CHG0030002"}}))
    assert (await ok_call(client, mint("user"), "change_list"))["count"] == 1
    out = await ok_call(client, mint("user"), "change_create_normal", {"short_description": "Patch routers"})
    assert out["created"]["number"] == "CHG0030002"
    body = json.loads(post.calls[0].request.content)
    assert body["type"] == "normal" and body["short_description"] == "[via MCP agent] Patch routers"


async def test_change_create_denied(client, mint, sn):
    router, _ = sn
    router.post(f"{SN}/api/now/table/change_request").mock(return_value=httpx.Response(
        403, json={"error": {"message": "Operation Failed", "detail": "ACL Exception Insert Failed due to security constraints"}}))
    msg = await err_call(client, mint("user"), "change_create_normal", {"short_description": "Nope"})
    assert "ServiceNow ACL denied" in msg


@pytest.mark.parametrize("status,fragment", [(401, "rejected the token"), (404, "not visible"),
                                             (503, "temporarily unavailable"), (400, "failed (400)")])
async def test_error_mapping(client, mint, sn, status, fragment):
    router, _ = sn
    router.get(f"{SN}/api/now/table/change_request").mock(return_value=httpx.Response(status, json={}))
    assert fragment in await err_call(client, mint("user"), "change_list")


USER_TOOLS = [("whoami", {}), ("incident_list", {}), ("incident_create", {"short_description": "abc"}),
              ("incident_add_work_note", {"number": "INC0010001", "note": "x"}), ("kb_search", {}),
              ("kb_get_article", {"number": "KB0010001"}), ("change_list", {}),
              ("change_create_normal", {"short_description": "abc"})]


async def test_m2m_refused_on_all_user_tools(client, mint, sn):
    router, _ = sn
    for name, args in USER_TOOLS:
        msg = await err_call(client, mint("m2m"), name, args)
        assert "machine" in msg.lower(), name
    assert router.routes[0].call_count == 0  # never attempted an exchange


async def test_tools_listed(client, mint):
    from conftest import MCP_HEADERS
    r = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                          headers={**MCP_HEADERS, "Authorization": f"Bearer {mint('user')}"})
    data = next(line[5:] for line in r.text.splitlines() if line.startswith("data:"))
    names = {t["name"] for t in json.loads(data)["result"]["tools"]}
    assert names == {"auth_info", *(n for n, _ in USER_TOOLS)}
