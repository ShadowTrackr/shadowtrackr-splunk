import json
import socket

import pytest

from mock_api.server import DEFAULT_API_KEY, GROUP_API_KEY, NO_ACCESS_KEY, org_for
from shadowtrackr_lib.client import (
    APIError,
    AuthError,
    ShadowTrackrClient,
    TransientError,
    build_proxy_url,
)


class FakeResponse:
    def __init__(self, status, payload=None, raw=None, content_type="application/json", headers=None):
        self.status = status
        self.data = raw if raw is not None else json.dumps(payload).encode("utf-8")
        self.headers = dict({"Content-Type": content_type}, **(headers or {}))


class FakeHTTP:
    """Stands in for urllib3.PoolManager and records requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def make_client(*responses, **kwargs):
    sleeps = []
    client = ShadowTrackrClient("k" * 32, base_url="https://api.test/api/v4", sleep=sleeps.append, **kwargs)
    client._http = FakeHTTP(*responses)
    return client, sleeps


def envelope(data=None, error=""):
    return {"results": "", "error": error, "data": data or []}


# --- unit tests with a fake transport -------------------------------------


def test_post_sends_bearer_token_and_json_body():
    client, _ = make_client(FakeResponse(200, envelope([{"a": 1}])))
    assert client.post("events", {"start": "x"}) == [{"a": 1}]
    method, url, kwargs = client._http.requests[0]
    assert method == "POST"
    assert url == "https://api.test/api/v4/events"
    assert kwargs["headers"]["Authorization"] == "Bearer " + "k" * 32
    assert json.loads(kwargs["body"]) == {"start": "x"}


def test_base_url_trailing_slash_is_ignored():
    client = ShadowTrackrClient("k" * 32, base_url="https://api.test/api/v4/")
    assert client.base_url == "https://api.test/api/v4"


def test_empty_api_key_is_rejected():
    with pytest.raises(AuthError):
        ShadowTrackrClient("")


def test_invalid_key_reported_with_http_200_raises_auth_error():
    client, _ = make_client(FakeResponse(200, envelope(error="Invalid API key")))
    with pytest.raises(AuthError, match="Invalid API key"):
        client.post("events")


def test_http_401_raises_auth_error():
    client, _ = make_client(FakeResponse(401, envelope(error="Unauthorized. No API key provided")))
    with pytest.raises(AuthError, match="Unauthorized"):
        client.post("events")


def test_other_envelope_error_raises_api_error():
    client, _ = make_client(FakeResponse(200, envelope(error="Something went wrong")))
    with pytest.raises(APIError, match="Something went wrong"):
        client.post("events")


def test_html_response_raises_api_error_pointing_at_base_url():
    client, _ = make_client(FakeResponse(404, raw=b"<!DOCTYPE html><html></html>", content_type="text/html"))
    with pytest.raises(APIError, match="base URL"):
        client.post("nope")


def test_non_list_data_raises_api_error():
    client, _ = make_client(FakeResponse(200, {"results": "", "error": "", "data": {"x": 1}}))
    with pytest.raises(APIError):
        client.post("events")


def test_missing_data_returns_empty_list():
    client, _ = make_client(FakeResponse(200, {"results": "", "error": ""}))
    assert client.post("events") == []


@pytest.mark.parametrize("status", [429, 500, 502, 503])
def test_transient_status_is_retried_then_succeeds(status):
    client, sleeps = make_client(FakeResponse(status, raw=b"busy"), FakeResponse(200, envelope([{"a": 1}])))
    assert client.post("events") == [{"a": 1}]
    assert sleeps == [2.0]


def test_transient_errors_give_up_after_max_retries_with_backoff():
    client, sleeps = make_client(*[FakeResponse(500, raw=b"err")] * 4)
    with pytest.raises(TransientError):
        client.post("events")
    assert sleeps == [2.0, 4.0, 8.0]


def test_auth_errors_are_not_retried():
    client, sleeps = make_client(FakeResponse(200, envelope(error="Invalid API key")))
    with pytest.raises(AuthError):
        client.post("events")
    assert sleeps == []


def test_network_error_is_transient_and_does_not_leak_the_key():
    import urllib3

    error = urllib3.exceptions.NewConnectionError(None, "Bearer " + "k" * 32)
    client, _ = make_client(error, max_retries=0)
    with pytest.raises(TransientError) as excinfo:
        client.post("events")
    assert "k" * 32 not in str(excinfo.value)


# --- proxy settings -------------------------------------------------------


def test_proxy_disabled_returns_none():
    assert build_proxy_url({"proxy_enabled": "0", "proxy_url": "proxy.local"}) is None
    assert build_proxy_url({}) is None


def test_proxy_url_with_credentials_is_escaped():
    url = build_proxy_url(
        {
            "proxy_enabled": "1",
            "proxy_type": "http",
            "proxy_url": "proxy.local",
            "proxy_port": "3128",
            "proxy_username": "user",
            "proxy_password": "p@ss:word",
        }
    )
    assert url == "http://user:p%40ss%3Aword@proxy.local:3128"


def test_socks_proxy_with_remote_dns():
    url = build_proxy_url({"proxy_enabled": "true", "proxy_type": "socks5", "proxy_url": "s.local", "proxy_rdns": "1"})
    assert url == "socks5h://s.local"


def test_retry_after_is_honoured():
    client, sleeps = make_client(
        FakeResponse(429, raw=b"", headers={"Retry-After": "30"}), FakeResponse(200, envelope([{"a": 1}]))
    )
    assert client.post("events") == [{"a": 1}]
    assert sleeps == [30.0]


def test_retry_after_is_capped():
    client, sleeps = make_client(
        FakeResponse(429, raw=b"", headers={"Retry-After": "86400"}), FakeResponse(200, envelope([]))
    )
    client.post("events")
    assert sleeps == [300]


@pytest.mark.parametrize("value", ["soon", "Wed, 21 Oct 2026 07:28:00 GMT", "-5"])
def test_unusable_retry_after_falls_back_to_backoff(value):
    client, sleeps = make_client(FakeResponse(429, raw=b"", headers={"Retry-After": value}),
                                 FakeResponse(200, envelope([])))
    client.post("events")
    assert sleeps == [2.0]


def test_http_403_raises_auth_error():
    client, _ = make_client(FakeResponse(403, envelope(error="API access is not enabled")))
    with pytest.raises(AuthError, match="not enabled"):
        client.post("events")


def test_json_404_and_400_raise_api_error():
    client, _ = make_client(FakeResponse(404, envelope(error="Unknown endpoint")),
                            FakeResponse(400, envelope(error="Unknown parameter: x")))
    with pytest.raises(APIError, match="Unknown endpoint"):
        client.post("nope")
    with pytest.raises(APIError, match="HTTP 400"):
        client.post("events", {"x": 1})


def test_events_since_returns_next_since_id():
    client, _ = make_client(FakeResponse(200, dict(envelope([{"id": 5}]), next_since_id=5)))
    assert client.events_since(0, 10) == ([{"id": 5}], 5)
    assert json.loads(client._http.requests[0][2]["body"]) == {"since_id": 0, "limit": 10}


def test_events_since_without_next_since_id_means_legacy_api():
    client, _ = make_client(FakeResponse(200, envelope([{"msg": "x"}])))
    assert client.events_since(0, 10)[1] is None


def test_request_returns_non_list_data():
    payload = {"results": "", "error": "", "data": {"organizations": []}}
    client, _ = make_client(FakeResponse(200, payload))
    assert client.request("organizations")["data"] == {"organizations": []}


# --- against the v4 mock server --------------------------------------------


def org_a(events):
    return [e for e in events if org_for(e)["name"] == "Customer A"]


def test_mock_events_window(mock_api, fixture_events):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    data = client.events("2026-10-09T00:00:00", "2026-10-10T00:00:00")
    expected = [e for e in org_a(fixture_events) if "2026-10-09T00:00:00Z" <= e["timestamp"] <= "2026-10-10T00:00:00Z"]
    assert len(data) == len(expected) > 0


def test_mock_since_id_paging(mock_api, fixture_events):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    collected, since = [], 0
    while True:
        page, since = client.events_since(since, 50)
        collected += page
        if len(page) < 50:
            break
    ids = [e["id"] for e in collected]
    assert ids == sorted(ids)
    assert len(ids) == len(org_a(fixture_events))
    assert client.events_since(since, 50) == ([], since)


def test_mock_latest_id(mock_api, fixture_events):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    assert client.latest_id() == max(e["id"] for e in org_a(fixture_events))


def test_mock_limit_alone_returns_newest(mock_api, fixture_events):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    envelope = client.request("events", {"limit": 3})
    times = [e["timestamp"] for e in envelope["data"]]
    assert len(times) == 3 and times == sorted(times, reverse=True)
    assert envelope["latest_id"] == max(e["id"] for e in org_a(fixture_events))


def test_mock_level_gte_includes_the_value(mock_api):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    gte = client.post("events", {"since_id": 0, "limit": 5000, "level_gte": 90})
    assert gte and all(e["level"] >= 90 for e in gte) and any(e["level"] == 90 for e in gte)


def test_mock_normal_key_has_no_organization(mock_api):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    page, _ = client.events_since(0, 10)
    assert page and all("organization" not in e for e in page)


def test_latest_id_is_none_on_legacy_api(mock_api_legacy):
    assert ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api_legacy).latest_id() is None


def test_mock_limit_is_clamped(mock_api):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    page, _ = client.events_since(0, 100000)
    assert len(page) > 0


def test_mock_group_key_sees_all_organizations(mock_api, fixture_events):
    client = ShadowTrackrClient(GROUP_API_KEY, base_url=mock_api)
    page, _ = client.events_since(0, 5000)
    assert {e["organization"]["name"] for e in page} == {"Customer A", "Customer B"}
    assert len(page) == len(fixture_events)


def test_mock_group_key_organization_filter(mock_api):
    client = ShadowTrackrClient(GROUP_API_KEY, base_url=mock_api)
    data = client.post("events", {"since_id": 0, "organization_id": 1470063})
    assert {e["organization"]["id"] for e in data} == {1470063}
    with pytest.raises(AuthError):
        client.post("events", {"since_id": 0, "organization_id": 999})


def test_mock_group_key_rejects_update_only(mock_api):
    client = ShadowTrackrClient(GROUP_API_KEY, base_url=mock_api)
    with pytest.raises(APIError, match="HTTP 400"):
        client.post("events", {"update_only": True})


def test_mock_min_level_is_strictly_greater(mock_api):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    data = client.post("events", {"since_id": 0, "limit": 5000, "min_level": 90})
    assert data and all(e["level"] > 90 for e in data)


def test_mock_event_types(mock_api, fixture_event_types):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    assert len(client.event_types()) == len(fixture_event_types)
    only = client.post("event_types", {"eventid": 1415})
    assert [t["name"] for t in only] == ["ssllabs_renewed_cert_problems"]


def test_mock_invalid_key_is_401(mock_api):
    client = ShadowTrackrClient("wrong-key-000000000", base_url=mock_api)
    with pytest.raises(AuthError, match="Invalid API key"):
        client.events_since(0, 10)


def test_mock_no_api_access_is_403(mock_api):
    client = ShadowTrackrClient(NO_ACCESS_KEY, base_url=mock_api)
    with pytest.raises(AuthError, match="not enabled"):
        client.events_since(0, 10)


def test_mock_unknown_endpoint_is_json_404(mock_api):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    with pytest.raises(APIError, match="Unknown endpoint"):
        client.post("does_not_exist")


def test_mock_unknown_parameter_is_400(mock_api):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    with pytest.raises(APIError, match="Unknown parameter"):
        client.post("events", {"bogus": 1})


def test_mock_429_with_retry_after(mock_api):
    sleeps = []
    client = ShadowTrackrClient("mock-error-429", base_url=mock_api, max_retries=1, sleep=sleeps.append)
    with pytest.raises(TransientError):
        client.post("events")
    assert sleeps == [2.0]  # Retry-After: 1 is shorter than our backoff


def test_mock_server_error_is_transient(mock_api):
    client = ShadowTrackrClient("mock-error-500", base_url=mock_api, max_retries=1, sleep=lambda s: None)
    with pytest.raises(TransientError):
        client.post("events")


def test_mock_html_with_200_is_api_error(mock_api):
    client = ShadowTrackrClient("mock-error-html", base_url=mock_api)
    with pytest.raises(APIError, match="base URL"):
        client.post("events")


def test_timeout_is_transient(mock_api):
    client = ShadowTrackrClient("mock-error-slow", base_url=mock_api, timeout=0.5, max_retries=0)
    with pytest.raises(TransientError):
        client.post("events")


def test_connection_refused_is_transient():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    client = ShadowTrackrClient("k" * 32, base_url="http://127.0.0.1:{}/api/v4".format(port), max_retries=0)
    with pytest.raises(TransientError):
        client.post("events")


# --- against the legacy mock server ----------------------------------------


def test_legacy_invalid_key_with_http_200(mock_api_legacy):
    client = ShadowTrackrClient("wrong-key-000000000", base_url=mock_api_legacy)
    with pytest.raises(AuthError):
        client.post("events")


def test_legacy_has_no_since_id(mock_api_legacy):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api_legacy)
    data, next_since_id = client.events_since(0, 10)
    assert next_since_id is None
    assert data and "id" not in data[0]


def test_legacy_unknown_endpoint_is_html(mock_api_legacy):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api_legacy)
    with pytest.raises(APIError, match="base URL"):
        client.event_types()
