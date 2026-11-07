import json
import logging
import os

import pytest

from mock_api.server import DEFAULT_API_KEY, GROUP_API_KEY
from shadowtrackr_lib.client import AuthError, ShadowTrackrClient, TransientError
from shadowtrackr_lib.inventory import InventoryCollector, KVStore, list_organizations, reconcile, validate_interval
from shadowtrackr_lib.inventory_types import TYPES, add_st_scores, enrich_cves, expand_internet_standards, merge_cloud_providers

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY = os.path.join(ROOT, "tests", "fixtures", "inventory")
DAY = 86400


def fixture(endpoint):
    with open(os.path.join(INVENTORY, endpoint + ".json"), encoding="utf-8") as f:
        return json.load(f)["data"]


def rows_for(name, records=None, org=None):
    t = TYPES[name]
    records = fixture(t.endpoint) if records is None else records
    for endpoint, combine in t.extra:
        records = combine(records, fixture(endpoint))
    return t.rows(records, org)


# --- projections and keys ---------------------------------------------------


@pytest.mark.parametrize("name", sorted(TYPES))
def test_every_type_projects_its_fixture(name):
    rows = rows_for(name)
    assert rows, "fixture for {} should produce rows".format(name)
    for row in rows:
        assert row["_key"] and len(row["_key"]) == 24
        if TYPES[name].fields:
            assert set(row) - {"_key"} <= set(TYPES[name].fields)
        for value in row.values():
            # Lookups take scalars or lists of scalars, never nested objects.
            assert not isinstance(value, dict)
            if isinstance(value, list):
                assert all(not isinstance(v, (dict, list)) for v in value)


@pytest.mark.parametrize("name", sorted(TYPES))
def test_keys_are_stable(name):
    assert [r["_key"] for r in rows_for(name)] == [r["_key"] for r in rows_for(name)]


def test_key_ignores_seen_dates_but_follows_the_natural_key():
    host = fixture("hosts")[0]
    a = TYPES["hosts"].rows([host])[0]["_key"]
    b = TYPES["hosts"].rows([dict(host, last_seen="2030-01-01T00:00:00Z", tags=["x"])])[0]["_key"]
    c = TYPES["hosts"].rows([dict(host, ip="198.51.100.250")])[0]["_key"]
    assert a == b != c


def test_generic_key_ignores_seen_dates():
    rec = fixture("blacklisted_assets")[0]
    a = TYPES["blacklisted_assets"].rows([rec])[0]["_key"]
    b = TYPES["blacklisted_assets"].rows([dict(rec, last_seen="2030-01-01T00:00:00Z")])[0]["_key"]
    assert a == b


def test_key_includes_organization():
    host = fixture("hosts")[:1]
    a = TYPES["hosts"].rows(host, {"id": 1, "name": "A"})[0]
    b = TYPES["hosts"].rows(host, {"id": 2, "name": "B"})[0]
    assert a["_key"] != b["_key"]
    assert a["organization"] == "A" and a["organization_id"] == 1


def test_duplicates_collapse():
    cve = fixture("cves_assets")[0]
    assert len(TYPES["cves"].rows([cve, dict(cve), dict(cve, last_seen="x")])) == 1


def test_host_projection():
    raw = next(h for h in fixture("hosts") if h.get("tcp"))
    row = TYPES["hosts"].rows([raw])[0]
    assert row["ip"] == raw["ip"]
    assert row["tcp_ports"] == [p["port"] for p in raw["tcp"]]
    assert all("/tcp" in s or "/udp" in s for s in row["services"])


def test_certificate_projection():
    raw = fixture("certificates")[0]
    row = TYPES["certificates"].rows([raw])[0]
    assert row["grade"] == raw["security_grade"]
    assert row["not_after"] == raw["not_valid_after"]
    assert row["sha256"] == raw["sha256hash"]
    assert set(row.get("weak_protocols", [])) <= set(row.get("protocols", []))


def test_cves_get_flags_from_vulnerabilities():
    cves = [{"cve": "CVE-1", "asset": "a", "software": "s"}, {"cve": "CVE-2", "asset": "a", "software": "s"}]
    vulns = [{"software": "s", "cves": [{"cve": "CVE-1", "exploited": True, "cisa": "1"}]}]
    rows = {r["cve"]: r for r in TYPES["cves"].rows(enrich_cves(cves, vulns))}
    assert rows["CVE-1"]["exploited"] is True and rows["CVE-1"]["cisa_kev"] is True
    assert rows["CVE-2"]["exploited"] is False


def test_cloud_providers_are_merged_per_provider():
    merged = merge_cloud_providers([
        {"cloud_provider": "Cloudflare", "assets": 2, "urls": ["a"], "first_seen": "2026-10-02", "last_seen": "x1"},
        {"cloud_provider": "Cloudflare", "assets": 3, "urls": ["b", "a"], "first_seen": "2026-10-01", "last_seen": "x2"},
    ])
    assert merged == [{"cloud_provider": "Cloudflare", "assets": 5, "urls": ["a", "b"],
                       "first_seen": "2026-10-01", "last_seen": "x2"}]


def test_internet_standards_one_row_per_check():
    raw = fixture("internet_standards")
    expected = sum(len(c["checks"]) for r in raw for c in r["checks"])
    rows = TYPES["internet_standards"].rows(raw)
    assert len(rows) == expected
    assert {"url", "category", "check", "passed"} <= set(rows[0])
    assert expand_internet_standards([{"url": "x", "checks": ["junk", {"checks": [None]}]}]) == []


def test_exposed_email_projection():
    raw = next(e for e in fixture("exposed_email_addresses") if e["breaches"])
    row = TYPES["exposed_emails"].rows([raw])[0]
    assert row["breach_count"] == len(raw["breaches"])
    assert row["latest_breach"] == max(b["breached"] for b in raw["breaches"])


def test_inventory_conf_is_in_sync_with_types():
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen", os.path.join(ROOT, "tools", "gen_inventory_conf.py"))
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    for name, block in (("collections.conf", gen.collections_block()), ("transforms.conf", gen.transforms_block())):
        path = os.path.join(ROOT, "package", "default", name)
        with open(path, encoding="utf-8") as f:
            assert f.read() == gen.render(path, block), "run tools/gen_inventory_conf.py"


# --- reconcile --------------------------------------------------------------

HOSTS = TYPES["hosts"]


def host_rows(n):
    return [dict(ip="192.0.2.{}".format(i), _key="k{}".format(i)) for i in range(n)]


def test_first_sync_marks_everything_new():
    result = reconcile(HOSTS, host_rows(3), [], now=1000, retention_seconds=30 * DAY, empty_runs=0)
    assert result["summary"] == {"type": "hosts", "status": "ok", "present": 3, "new": 3, "gone": 0, "deleted": 0}
    assert all(r["st_first_synced"] == 1000 and r["st_present"] == 1 for r in result["save"])


def test_resync_keeps_first_synced():
    first = reconcile(HOSTS, host_rows(2), [], 1000, 30 * DAY, 0)["save"]
    second = reconcile(HOSTS, host_rows(2), first, 2000, 30 * DAY, 0)
    assert second["summary"]["new"] == 0
    assert {r["st_first_synced"] for r in second["save"]} == {1000}
    assert {r["st_last_synced"] for r in second["save"]} == {2000}


def test_missing_rows_are_marked_gone_then_deleted_after_retention():
    stored = reconcile(HOSTS, host_rows(3), [], 1000, 30 * DAY, 0)["save"]
    result = reconcile(HOSTS, host_rows(2), stored, 2000, 30 * DAY, 0)
    gone = [r for r in result["save"] if r["st_present"] == 0]
    assert result["summary"]["gone"] == 1 and len(gone) == 1 and gone[0]["st_last_synced"] == 1000
    stored = {r["_key"]: r for r in stored}
    stored.update({r["_key"]: r for r in result["save"]})

    still = reconcile(HOSTS, host_rows(2), list(stored.values()), 1000 + 29 * DAY, 30 * DAY, 0)
    assert still["delete"] == []
    later = reconcile(HOSTS, host_rows(2), list(stored.values()), 1000 + 31 * DAY, 30 * DAY, 0)
    assert later["delete"] == [gone[0]["_key"]] and later["summary"]["deleted"] == 1


def test_returning_row_is_present_again_without_counting_as_new():
    stored = reconcile(HOSTS, host_rows(2), [], 1000, 30 * DAY, 0)["save"]
    gone = reconcile(HOSTS, host_rows(1), stored, 2000, 30 * DAY, 0)["save"]
    back = reconcile(HOSTS, host_rows(2), gone, 3000, 30 * DAY, 0)
    assert back["summary"]["new"] == 0
    assert all(r["st_present"] == 1 for r in back["save"])
    assert next(r for r in back["save"] if r["_key"] == "k1")["st_first_synced"] == 1000


def test_empty_result_needs_two_runs_before_rows_are_gone():
    stored = reconcile(HOSTS, host_rows(3), [], 1000, 30 * DAY, 0)["save"]
    first = reconcile(HOSTS, [], stored, 2000, 30 * DAY, 0)
    assert first["summary"]["status"] == "skipped_empty" and first["summary"]["gone"] == 0
    assert first["save"] == [] and first["empty_runs"] == 1
    second = reconcile(HOSTS, [], stored, 3000, 30 * DAY, first["empty_runs"])
    assert second["summary"]["status"] == "ok" and second["summary"]["gone"] == 3


def test_empty_type_that_was_empty_is_fine():
    result = reconcile(HOSTS, [], [], 1000, 30 * DAY, 0)
    assert result["summary"]["status"] == "ok" and result["save"] == []


def test_reconcile_only_touches_its_organization():
    a = [dict(r, organization_id=1) for r in host_rows(2)]
    b = [dict(ip="198.51.100.1", _key="b1", organization_id=2, st_present=1, st_last_synced=1)]
    result = reconcile(HOSTS, a[:1], a + b, 2000, 30 * DAY, 0, organization_id=1)
    assert result["summary"]["gone"] == 1
    assert all(r.get("organization_id") == 1 for r in result["save"])


# --- collector ----------------------------------------------------------------


class FakeKV(KVStore):
    def __init__(self, fail=()):
        self.data = {}
        self.fail = set(fail)

    def load(self, collection):
        if collection in self.fail:
            raise RuntimeError("KV Store is not ready")
        return [dict(r) for r in self.data.get(collection, {}).values()]

    def save(self, collection, rows):
        self.data.setdefault(collection, {}).update({r["_key"]: dict(r) for r in rows})

    def delete(self, collection, keys):
        for key in keys:
            self.data.get(collection, {}).pop(key, None)


class FixtureClient:
    """Serves the inventory fixtures; a normal (non-group) key."""

    def __init__(self, overrides=None, fail=()):
        self.overrides = overrides or {}
        self.fail = set(fail)
        self.calls = []

    def request(self, endpoint, body):
        from shadowtrackr_lib.client import APIError

        raise APIError("organizations: Error: No groupcode provided")

    def post(self, endpoint, body=None):
        self.calls.append((endpoint, body))
        if endpoint in self.fail:
            raise TransientError("HTTP 500 from " + endpoint)
        if endpoint in self.overrides:
            return self.overrides[endpoint]
        return fixture(endpoint)


def collector(client, kv, state, now=1000.0, types=None):
    return InventoryCollector(
        client=client, kv=kv, load_state=lambda: state.get("s"), save_state=lambda s: state.__setitem__("s", s),
        logger=logging.getLogger("test"), types=types or list(TYPES), retention_days=30, now=lambda: now,
    )


def test_full_run_fills_every_collection():
    kv, state = FakeKV(), {}
    summaries = collector(FixtureClient(), kv, state).run()
    assert {s["type"] for s in summaries} == set(TYPES)
    assert all(s["status"] == "ok" for s in summaries)
    for name, t in TYPES.items():
        assert len(kv.data[t.collection]) == next(s["present"] for s in summaries if s["type"] == name)


def test_second_run_has_no_new_rows():
    kv, state = FakeKV(), {}
    collector(FixtureClient(), kv, state).run()
    summaries = collector(FixtureClient(), kv, state, now=2000.0).run()
    assert sum(s["new"] for s in summaries) == 0 and sum(s["gone"] for s in summaries) == 0


def test_failing_type_does_not_stop_the_others():
    kv, state = FakeKV(), {}
    summaries = {s["type"]: s for s in collector(FixtureClient(fail={"certificates"}), kv, state).run()}
    assert summaries["certificates"]["status"] == "error"
    assert summaries["hosts"]["status"] == "ok"
    assert TYPES["certificates"].collection not in kv.data


def test_unreadable_collection_is_reported():
    kv, state = FakeKV(fail={"shadowtrackr_hosts"}), {}
    summaries = {s["type"]: s for s in collector(FixtureClient(), kv, state).run()}
    assert summaries["hosts"]["status"] == "error" and summaries["urls"]["status"] == "ok"


def test_auth_error_stops_the_run():
    class Unauthorized(FixtureClient):
        def post(self, endpoint, body=None):
            raise AuthError("Invalid API key")

    with pytest.raises(AuthError):
        collector(Unauthorized(), FakeKV(), {}).run()


def test_empty_guard_state_survives_between_runs():
    kv, state = FakeKV(), {}
    collector(FixtureClient(), kv, state, types=["hosts"]).run()
    empty = FixtureClient(overrides={"hosts": []})
    first = collector(empty, kv, state, now=2000.0, types=["hosts"]).run()[0]
    second = collector(empty, kv, state, now=3000.0, types=["hosts"]).run()[0]
    assert first["status"] == "skipped_empty" and second["gone"] == len(fixture("hosts"))


def test_only_selected_types_are_synced():
    client = FixtureClient()
    collector(client, FakeKV(), {}, types=["hosts", "cves", "nonsense"]).run()
    # CVEs also read hosts and websites for the ShadowTrackr score; hosts comes from the run's cache.
    assert [c[0] for c in client.calls] == ["hosts", "cves_assets", "vulnerabilities", "websites"]


# --- against the mock server --------------------------------------------------


def test_mock_normal_key(mock_api):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    assert list_organizations(client) is None
    kv = FakeKV()
    summaries = collector(client, kv, {}).run()
    assert all(s["status"] == "ok" for s in summaries)
    assert all("organization" not in r for r in kv.data["shadowtrackr_hosts"].values())


def test_mock_group_key_syncs_each_organization(mock_api):
    client = ShadowTrackrClient(GROUP_API_KEY, base_url=mock_api)
    orgs = list_organizations(client)
    assert [o["name"] for o in orgs] == ["Customer A", "Customer B"]
    kv = FakeKV()
    summaries = collector(client, kv, {}, types=["hosts"]).run()
    assert [(s["organization"], s["present"]) for s in summaries] == [
        ("Customer A", len(fixture("hosts"))), ("Customer B", 3)]
    hosts = kv.data["shadowtrackr_hosts"].values()
    assert {h["organization"] for h in hosts} == {"Customer A", "Customer B"}


@pytest.mark.parametrize("value", ["3600", "43200", 604800, "0 7,10,13,16 * * 1-5", "*/30 * * * *", " 0 7 * * 1-5 "])
def test_validate_interval_accepts(value):
    validate_interval(value)


@pytest.mark.parametrize("value", ["900", "3599", "604801", "-1", "", None, "abc", "0 7 * *", "0 7 * * 1-5 2026"])
def test_validate_interval_rejects(value):
    with pytest.raises(ValueError):
        validate_interval(value)


def test_add_st_scores_from_hosts_and_websites():
    records = [{"cve": "CVE-1", "asset": "192.0.2.1"}, {"cve": "CVE-2", "asset": "www.example.com"},
               {"cve": "CVE-3", "asset": "192.0.2.1"}]
    hosts = [{"ip": "192.0.2.1", "vulnerabilities": [
        {"name": "OpenSSH 8.9", "vulnerabilities": [{"cve": "CVE-1", "shadowtrackr_cvss_score": 7.2}]}]}]
    websites = [{"url": "www.example.com", "vulnerabilities": [
        {"name": "Next.js 13", "vulnerabilities": [{"name": "CVE-2", "shadowtrackr_cvss_score": 4.6},
                                                   {"name": "CVE-9", "shadowtrackr_cvss_score": True}]}]},
                {"url": "x", "vulnerabilities": ""}]
    out = add_st_scores(add_st_scores(records, hosts), websites)
    assert [r.get("shadowtrackr_cvss_score") for r in out] == [7.2, 4.6, None]
    rows = TYPES["cves"].rows(out)
    assert sorted(r.get("st_score") for r in rows if "st_score" in r) == [4.6, 7.2]

