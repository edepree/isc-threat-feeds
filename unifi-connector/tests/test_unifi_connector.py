import pathlib
import unittest.mock

import pytest
import requests

import unifi_connector

BASE = {"UNIFI_URL": "https://10.0.0.1/proxy/network/integration", "UNIFI_API_KEY": "k", "FEEDS": "bots"}


def test_load_config_defaults() -> None:
    assert unifi_connector.load_config(BASE) == unifi_connector.Config(
        url=BASE["UNIFI_URL"], api_key="k", feeds=("bots",), site="default", verify=True
    )


@pytest.mark.parametrize("missing", ["UNIFI_URL", "UNIFI_API_KEY", "FEEDS"])
def test_load_config_missing_required(missing: str) -> None:
    with pytest.raises(unifi_connector.ConfigError, match=missing):
        unifi_connector.load_config({k: v for k, v in BASE.items() if k != missing})


def test_load_config_blank_required_is_missing() -> None:
    with pytest.raises(unifi_connector.ConfigError, match="UNIFI_API_KEY"):
        unifi_connector.load_config({**BASE, "UNIFI_API_KEY": ""})


def test_load_config_rejects_unknown_feed() -> None:
    with pytest.raises(unifi_connector.ConfigError, match="nope"):
        unifi_connector.load_config({**BASE, "FEEDS": "bots,nope"})


def test_load_config_rejects_empty_feeds() -> None:
    with pytest.raises(unifi_connector.ConfigError, match="FEEDS"):
        unifi_connector.load_config({**BASE, "FEEDS": " , "})


def test_load_config_normalizes_feeds() -> None:
    assert unifi_connector.load_config({**BASE, "FEEDS": " bots, Malware,bots "}).feeds == ("bots", "malware")


def test_load_config_strips_trailing_slash() -> None:
    assert unifi_connector.load_config({**BASE, "UNIFI_URL": BASE["UNIFI_URL"] + "/"}).url == BASE["UNIFI_URL"]


def test_load_config_site_override() -> None:
    assert unifi_connector.load_config({**BASE, "UNIFI_SITE": "Home"}).site == "Home"


@pytest.mark.parametrize(("value", "expected"), [("true", True), ("FALSE", False), ("True", True)])
def test_load_config_verify_bool(value: str, expected: bool) -> None:
    assert unifi_connector.load_config({**BASE, "UNIFI_VERIFY_TLS": value}).verify is expected


def test_load_config_verify_ca_path(tmp_path: pathlib.Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    assert unifi_connector.load_config({**BASE, "UNIFI_VERIFY_TLS": str(ca)}).verify == str(ca)


def test_load_config_verify_missing_path() -> None:
    with pytest.raises(unifi_connector.ConfigError, match="UNIFI_VERIFY_TLS"):
        unifi_connector.load_config({**BASE, "UNIFI_VERIFY_TLS": "/nope/ca.pem"})


def test_parse_feed_valid() -> None:
    assert unifi_connector.parse_feed("10.0.0.0/8\r\n\n1.2.3.4/32\n1.2.3.4/32\n") == ["1.2.3.4/32", "10.0.0.0/8"]


@pytest.mark.parametrize("text", ["::1/128\n", "<html>\n", "1.2.3.4/32\nnot-an-ip\n"])
def test_parse_feed_rejects_invalid_lines(text: str) -> None:
    with pytest.raises(ValueError):
        unifi_connector.parse_feed(text)


def test_parse_feed_rejects_empty() -> None:
    with pytest.raises(ValueError, match="empty"):
        unifi_connector.parse_feed("\n\n")


def test_fetch_feed_uses_raw_url() -> None:
    session = unittest.mock.Mock(spec=requests.Session)
    session.get.return_value.text = "1.2.3.4/32\n"

    assert unifi_connector.fetch_feed(session, "bots") == ["1.2.3.4/32"]
    session.get.assert_called_once_with(unifi_connector.FEED_URL.format(feed="bots"), timeout=30)


def test_fetch_feed_http_error() -> None:
    session = unittest.mock.Mock(spec=requests.Session)
    session.get.return_value.raise_for_status.side_effect = requests.HTTPError("404")

    with pytest.raises(requests.HTTPError):
        unifi_connector.fetch_feed(session, "bots")


def test_feed_session_has_no_api_key() -> None:
    session = unifi_connector.feed_session()
    assert "X-API-KEY" not in session.headers
    assert session.verify is True


def fake_response(status: int = 200, payload: object = None, text: str | None = None) -> unittest.mock.Mock:
    response = unittest.mock.Mock(spec=requests.Response)
    response.status_code = status
    if text is None:
        response.json.return_value = payload
        response.content = b"" if payload is None else b"{}"
        response.text = ""
    else:
        response.json.side_effect = requests.JSONDecodeError("bad", text, 0)
        response.content = text.encode()
        response.text = text
    return response


def make_client(*responses: unittest.mock.Mock) -> tuple[unifi_connector.UnifiClient, unittest.mock.Mock]:
    session = unittest.mock.Mock(spec=requests.Session)
    session.headers = {}
    session.request.side_effect = list(responses)
    return unifi_connector.UnifiClient("https://u/integration", "SECRET", verify=False, session=session), session


def page(data: list[dict], offset: int, total: int) -> unittest.mock.Mock:
    return fake_response(
        payload={"data": data, "offset": offset, "limit": 200, "count": len(data), "totalCount": total}
    )


def test_client_sets_headers_and_verify() -> None:
    _client, session = make_client()
    assert session.headers["X-API-KEY"] == "SECRET"
    assert session.headers["Accept"] == "application/json"


def test_request_disables_redirects_and_passes_verify() -> None:
    client, session = make_client(fake_response(payload={"ok": True}))
    assert client.request("GET", "/v1/info") == {"ok": True}
    assert session.request.call_args.kwargs["allow_redirects"] is False
    assert session.request.call_args.kwargs["verify"] is False


def test_request_redirect_is_an_error() -> None:
    client, _session = make_client(fake_response(302, text="Found"))
    with pytest.raises(unifi_connector.UnifiError, match="302 Found"):
        client.request("GET", "/v1/sites")


def test_unifi_error_json_body() -> None:
    response = fake_response(
        401,
        {
            "statusCode": 401,
            "statusName": "UNAUTHORIZED",
            "code": "api.authentication.missing-credentials",
            "message": "Missing credentials",
            "requestId": "r1",
        },
    )
    assert (
        unifi_connector.format_error(response)
        == "401 api.authentication.missing-credentials Missing credentials requestId=r1"
    )


def test_unifi_error_non_json_body() -> None:
    text = "<html>" * 100
    assert unifi_connector.format_error(fake_response(502, text=text)) == f"502 {text[:200]}"


def test_request_raises_unifi_error() -> None:
    client, _session = make_client(fake_response(502, text="Bad Gateway"))
    with pytest.raises(unifi_connector.UnifiError, match="502 Bad Gateway"):
        client.request("GET", "/v1/sites")


def test_paginate_collects_pages() -> None:
    first = [{"id": str(i)} for i in range(200)]
    second = [{"id": str(i)} for i in range(200, 250)]
    client, session = make_client(page(first, 0, 250), page(second, 200, 250))

    assert client.paginate("/v1/sites") == first + second
    offsets = [c.kwargs["params"] for c in session.request.call_args_list]
    assert offsets == [{"offset": 0, "limit": 200}, {"offset": 200, "limit": 200}]
    assert session.request.call_args.args == ("GET", "https://u/integration/v1/sites")
    assert session.request.call_args.kwargs["timeout"] == 30  # noqa: PLR2004


def test_site_id_matches_internal_reference() -> None:
    client, _session = make_client(page([{"id": "s1", "name": "Home", "internalReference": "default"}], 0, 1))
    assert client.site_id("default") == "s1"


def test_site_id_matches_name() -> None:
    client, _session = make_client(page([{"id": "s1", "name": "Home", "internalReference": "default"}], 0, 1))
    assert client.site_id("Home") == "s1"


def test_site_id_not_found() -> None:
    client, _session = make_client(page([], 0, 0))
    with pytest.raises(unifi_connector.UnifiError, match="site not found: default"):
        client.site_id("default")


def test_lists_returns_raw_objects() -> None:
    lists = [{"id": "L1", "name": "isc-bots"}, {"id": "L2", "name": "isc-bots"}]
    client, session = make_client(page(lists, 0, 2))
    assert client.lists("s") == lists
    assert session.request.call_args.args == ("GET", "https://u/integration/v1/sites/s/traffic-matching-lists")


def test_create_list_posts_body() -> None:
    client, session = make_client(fake_response(201, {"id": "L1"}))
    client.create_list("s", "isc-bots", ["1.2.3.4/32", "5.6.7.8/31"])
    session.request.assert_called_once_with(
        "POST",
        "https://u/integration/v1/sites/s/traffic-matching-lists",
        json={
            "type": "IPV4_ADDRESSES",
            "name": "isc-bots",
            "items": [{"type": "IP_ADDRESS", "value": "1.2.3.4"}, {"type": "SUBNET", "value": "5.6.7.8/31"}],
        },
        timeout=30,
        verify=False,
        allow_redirects=False,
    )


def test_update_list_puts_body() -> None:
    client, session = make_client(fake_response(200, {"id": "L1"}))
    client.update_list("s", "L1", "isc-bots", ["1.2.3.4/32"])
    session.request.assert_called_once_with(
        "PUT",
        "https://u/integration/v1/sites/s/traffic-matching-lists/L1",
        json=unifi_connector.list_body("isc-bots", ["1.2.3.4/32"]),
        timeout=30,
        verify=False,
        allow_redirects=False,
    )


def existing_list(list_id: str = "L1", items: list[dict] | None = None, list_type: str = "IPV4_ADDRESSES") -> dict:
    items = [{"type": "SUBNET", "value": "1.2.3.4/32"}] if items is None else items
    return {"id": list_id, "name": "isc-bots", "type": list_type, "items": items}


def test_sync_feed_creates_missing() -> None:
    client = unittest.mock.Mock(spec=unifi_connector.UnifiClient)
    line = unifi_connector.sync_feed(client, "s", "bots", ["1.2.3.4/32"], [])
    client.create_list.assert_called_once_with("s", "isc-bots", ["1.2.3.4/32"])
    assert line == "bots: created (+1 -0, 1 entries)"


def test_sync_feed_unchanged_normalizes() -> None:
    client = unittest.mock.Mock(spec=unifi_connector.UnifiClient)
    existing = [existing_list(items=[{"type": "IP_ADDRESS", "value": "1.2.3.4"}])]
    line = unifi_connector.sync_feed(client, "s", "bots", ["1.2.3.4/32"], existing)
    client.create_list.assert_not_called()
    client.update_list.assert_not_called()
    assert line == "bots: unchanged (+0 -0, 1 entries)"


def test_sync_feed_updates_changed() -> None:
    client = unittest.mock.Mock(spec=unifi_connector.UnifiClient)
    line = unifi_connector.sync_feed(client, "s", "bots", ["5.6.7.8/32"], [existing_list()])
    client.update_list.assert_called_once_with("s", "L1", "isc-bots", ["5.6.7.8/32"])
    assert line == "bots: updated (+1 -1, 1 entries)"


def test_sync_feed_updates_unknown_item_types() -> None:
    client = unittest.mock.Mock(spec=unifi_connector.UnifiClient)
    items = [{"type": "SUBNET", "value": "1.2.3.4/32"}, {"type": "IP_ADDRESS_RANGE", "start": "a", "stop": "b"}]
    line = unifi_connector.sync_feed(client, "s", "bots", ["1.2.3.4/32"], [existing_list(items=items)])
    client.update_list.assert_called_once()
    assert line == "bots: updated (+0 -1, 1 entries)"


def test_sync_feed_wrong_type_fails() -> None:
    client = unittest.mock.Mock(spec=unifi_connector.UnifiClient)
    with pytest.raises(ValueError, match="PORTS"):
        unifi_connector.sync_feed(client, "s", "bots", ["1.2.3.4/32"], [existing_list(list_type="PORTS")])
    client.create_list.assert_not_called()
    client.update_list.assert_not_called()


def test_sync_feed_duplicate_names_fails() -> None:
    client = unittest.mock.Mock(spec=unifi_connector.UnifiClient)
    with pytest.raises(ValueError, match="2 lists named isc-bots"):
        unifi_connector.sync_feed(client, "s", "bots", ["1.2.3.4/32"], [existing_list("L1"), existing_list("L2")])
    client.create_list.assert_not_called()
    client.update_list.assert_not_called()


MAIN_ENV = {**BASE, "UNIFI_API_KEY": "SECRETKEY", "FEEDS": "bots,malware"}


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> unittest.mock.Mock:
    client = unittest.mock.Mock(spec=unifi_connector.UnifiClient)
    client.site_id.return_value = "s"
    client.lists.return_value = []
    factory = unittest.mock.Mock(return_value=client)
    monkeypatch.setattr(unifi_connector, "UnifiClient", factory)
    monkeypatch.setattr(unifi_connector, "fetch_feed", lambda _session, _feed: ["1.2.3.4/32"])
    return factory


def test_main_downloads_without_api_key(fake_client: unittest.mock.Mock, monkeypatch: pytest.MonkeyPatch) -> None:
    sessions: list[requests.Session] = []

    def fetch(session: requests.Session, _feed: str) -> list[str]:
        sessions.append(session)
        return ["1.2.3.4/32"]

    monkeypatch.setattr(unifi_connector, "fetch_feed", fetch)
    assert unifi_connector.main({**MAIN_ENV, "UNIFI_VERIFY_TLS": "false"}) == 0
    assert sessions
    assert all("X-API-KEY" not in s.headers and s.verify is True for s in sessions)


def test_main_malformed_list_fails_only_that_feed(fake_client: unittest.mock.Mock) -> None:
    fake_client.return_value.lists.return_value = [{"name": "isc-bots", "type": "IPV4_ADDRESSES", "items": []}]
    assert unifi_connector.main(MAIN_ENV) == 1
    assert [c.args[1] for c in fake_client.return_value.create_list.call_args_list] == ["isc-malware"]


def test_main_bad_config_returns_2(fake_client: unittest.mock.Mock) -> None:
    assert unifi_connector.main({**MAIN_ENV, "FEEDS": "nope"}) == 2  # noqa: PLR2004
    fake_client.assert_not_called()


def test_main_all_ok_returns_0(fake_client: unittest.mock.Mock, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO")
    assert unifi_connector.main(MAIN_ENV) == 0
    fake_client.assert_called_once_with(MAIN_ENV["UNIFI_URL"], "SECRETKEY", True)
    client = fake_client.return_value
    assert [c.args[1] for c in client.create_list.call_args_list] == ["isc-bots", "isc-malware"]
    assert "bots: created (+1 -0, 1 entries)" in caplog.text
    assert "SECRETKEY" not in caplog.text


def test_main_continues_after_feed_failure(
    fake_client: unittest.mock.Mock, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fetch(_session: requests.Session, feed: str) -> list[str]:
        if feed == "bots":
            raise requests.ConnectionError("down")
        return ["1.2.3.4/32"]

    monkeypatch.setattr(unifi_connector, "fetch_feed", fetch)
    assert unifi_connector.main(MAIN_ENV) == 1
    assert [c.args[1] for c in fake_client.return_value.create_list.call_args_list] == ["isc-malware"]
    assert "bots: failed: down" in caplog.text
    assert "SECRETKEY" not in caplog.text


def test_main_site_lookup_failure_returns_1(fake_client: unittest.mock.Mock, caplog: pytest.LogCaptureFixture) -> None:
    fake_client.return_value.site_id.side_effect = unifi_connector.UnifiError("401 api.auth Missing credentials")
    assert unifi_connector.main(MAIN_ENV) == 1
    fake_client.return_value.create_list.assert_not_called()
    assert "401 api.auth Missing credentials" in caplog.text
    assert "SECRETKEY" not in caplog.text


def test_main_insecure_warns_once(fake_client: unittest.mock.Mock, caplog: pytest.LogCaptureFixture) -> None:
    assert unifi_connector.main({**MAIN_ENV, "UNIFI_VERIFY_TLS": "false"}) == 0
    assert caplog.text.count("TLS verification is disabled") == 1
    assert fake_client.call_args.args[2] is False
