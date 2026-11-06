import pytest

from shadowtrackr_lib.client import AuthError, ShadowTrackrClient
from shadowtrackr_lib.query import choose_account, parse_time, run_query, to_result, to_results

from mock_api import server as mock_server


def test_parse_time():
    assert parse_time("2026-11-06T04:37:02Z") == 1793939822.0
    assert parse_time("2026-11-06 04:37:02") == 1793939822.0
    assert parse_time("2026-11-06T06:37:02+02:00") == 1793939822.0
    assert parse_time("") is None
    assert parse_time("yesterday") is None
    assert parse_time(None) is None


def test_to_result_splits_list_fields_and_converts_values():
    result = to_result({
        "ip": "192.0.2.1",
        "tcp_ports": "22,80, 443",
        "software": "OpenSSH 8.0,cPanel",
        "tags": "",
        "message": "Found a, b and c",  # not a list field: commas stay
        "problem": False,
        "vulnerable": True,
        "asn": 12488,
        "whois": {"registrar": "X"},
        "history": [[301, "https://example.com/"]],
        "nameservers": ["ns1.example.com", "ns2.example.com"],
        "organization": None,
        "_internal": "dropped",
        "last_seen": "2026-11-06T04:37:02Z",
    })
    assert result["tcp_ports"] == ["22", "80", "443"]
    assert result["software"] == ["OpenSSH 8.0", "cPanel"]
    assert "tags" not in result
    assert result["message"] == "Found a, b and c"
    assert result["problem"] == 0 and result["vulnerable"] == 1
    assert result["asn"] == 12488
    assert result["whois"] == '{"registrar": "X"}'
    assert result["history"] == '[[301, "https://example.com/"]]'
    assert result["nameservers"] == ["ns1.example.com", "ns2.example.com"]
    assert "organization" not in result and "_internal" not in result
    assert result["_time"] == 1793939822.0


def test_single_list_value_stays_a_string():
    assert to_result({"software": "nginx"})["software"] == "nginx"


def test_time_falls_back_to_created():
    assert to_result({"created": "2026-11-06T04:37:02Z", "last_seen": ""})["_time"] == 1793939822.0
    assert "_time" not in to_result({"country": "Germany", "count": 3})


def test_to_results_gives_every_result_the_same_fields():
    results = to_results([{"a": 1, "last_seen": "2026-11-06T04:37:02Z"}, {"b": 2}, "not a row"])
    assert len(results) == 2
    assert list(results[0]) == ["_time", "a", "last_seen", "b"]
    assert list(results[1]) == ["_time", "a", "last_seen", "b"]
    assert results[1] == {"_time": None, "a": None, "last_seen": None, "b": 2}


class FakeClient:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def post(self, endpoint, body):
        self.calls.append((endpoint, body))
        return self.rows


def test_run_query_sends_q_and_limits():
    client = FakeClient([{"n": i} for i in range(5)])
    results, total = run_query(client, "  index=hosts  ", max_results=3)
    assert client.calls == [("query", {"q": "index=hosts"})]
    assert total == 5 and [r["n"] for r in results] == [0, 1, 2]
    results, total = run_query(client, "index=hosts", max_results=0)
    assert len(results) == 5


def test_run_query_needs_a_query():
    with pytest.raises(ValueError):
        run_query(FakeClient([]), "  ")


def test_choose_account():
    assert choose_account(["prod"], None) == ("prod", None)
    assert choose_account(["a", "b"], "b") == ("b", None)
    name, warning = choose_account(["a", "b"], None)
    assert name == "a" and "account=<name>" in warning and "a, b" in warning
    with pytest.raises(ValueError, match="No ShadowTrackr account named 'c'"):
        choose_account(["a", "b"], "c")
    with pytest.raises(ValueError, match="Configuration > Accounts"):
        choose_account([], None)


# --- against the mock API -----------------------------------------------------


def _client(url, key=mock_server.DEFAULT_API_KEY):
    return ShadowTrackrClient(key, base_url=url, max_retries=0)


def test_query_against_mock(mock_api):
    results, total = run_query(_client(mock_api), "index=hosts ip=192.0.2.24")
    assert total == 1
    host = results[0]
    assert host["ip"] == "192.0.2.24"
    assert host["tcp_ports"] == ["22", "80", "443", "3000"]
    assert host["vulnerable"] == 1
    assert host["_time"] == parse_time("2026-10-31T04:24:50Z")


def test_grouped_query_against_mock(mock_api):
    results, _ = run_query(_client(mock_api), "index=hosts by country")
    assert results and set(results[0]) == {"country", "count"}
    assert sum(r["count"] for r in results) == 25


def test_elastic_style_and_wildcards_against_mock(mock_api):
    results, _ = run_query(_client(mock_api), "websites.url:*.example.com AND warning=yes")
    assert results and all(r["url"].endswith(".example.com") and r["warning"] == 1 for r in results)


def test_unknown_index_gives_no_results(mock_api):
    assert run_query(_client(mock_api), "index=nonsense") == ([], 0)


def test_group_key_rows_carry_organization(mock_api):
    results, _ = run_query(_client(mock_api, mock_server.GROUP_API_KEY), "index=domains")
    assert results and all(r["organization"] == "Customer A" for r in results)


def test_query_with_bad_key(mock_api):
    with pytest.raises(AuthError):
        run_query(_client(mock_api, "wrong-key"), "index=hosts")
