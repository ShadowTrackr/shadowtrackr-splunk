import json
import socket

import pytest

from mock_api.server import DEFAULT_API_KEY
from shadowtrackr_lib.client import (
    APIError,
    AuthError,
    ShadowTrackrClient,
    TransientError,
    build_proxy_url,
)


class FakeResponse:
    def __init__(self, status, payload=None, raw=None, content_type="application/json"):
        self.status = status
        self.data = raw if raw is not None else json.dumps(payload).encode("utf-8")
        self.headers = {"Content-Type": content_type}


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


# --- against the mock server ----------------------------------------------


def test_mock_events_window(mock_api, fixture_events):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    data = client.events("2026-10-09T00:00:00", "2026-10-10T00:00:00")
    expected = [e for e in fixture_events if "2026-10-09T00:00:00Z" <= e["timestamp"] <= "2026-10-10T00:00:00Z"]
    assert len(data) == len(expected) > 0


def test_mock_invalid_key(mock_api):
    client = ShadowTrackrClient("wrong-key-000000000", base_url=mock_api)
    with pytest.raises(AuthError):
        client.events("2026-10-09T00:00:00", "2026-10-10T00:00:00")


def test_mock_unknown_endpoint(mock_api):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    with pytest.raises(APIError):
        client.post("does_not_exist")


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
