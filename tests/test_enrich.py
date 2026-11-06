import json
import os

import pytest

from shadowtrackr_lib.enrich import FIELDS, Enricher, apply, normalize, parent_domains, worst_grade
from shadowtrackr_lib.inventory_types import TYPES

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "inventory")


class FakeKV:
    """KV Store lookups with {field: {"$in": values}} semantics: a multivalue field
    matches when any of its values is in the list. Counts the calls."""

    def __init__(self, collections):
        self.collections = collections
        self.calls = []

    def __call__(self, collection, field, values):
        self.calls.append((collection, field, tuple(values)))
        wanted = set(values)
        out = []
        for row in self.collections.get(collection, []):
            value = row.get(field)
            items = value if isinstance(value, list) else [value]
            if any(v in wanted for v in items):
                out.append(row)
        return out


def _inventory(name, extra=()):
    inv_type = TYPES[name]
    with open(os.path.join(FIXTURES, inv_type.endpoint + ".json"), encoding="utf-8") as f:
        records = json.load(f)["data"]
    if inv_type.extra:
        endpoint, combine = inv_type.extra
        with open(os.path.join(FIXTURES, endpoint + ".json"), encoding="utf-8") as f:
            records = combine(records, json.load(f)["data"])
    rows = [dict(r, st_present=1) for r in inv_type.rows(records, None)]
    return rows + list(extra)


@pytest.fixture(scope="module")
def kv_data():
    data = {TYPES[n].collection: _inventory(n) for n in
            ("hosts", "websites", "certificates", "urls", "dns", "cves", "domains", "phishy_domains")}
    # A host that ShadowTrackr no longer reports must not count.
    data["shadowtrackr_hosts"].append({"ip": "198.51.100.99", "st_present": 0, "tcp_ports": [22]})
    return data


@pytest.fixture
def kv(kv_data):
    return FakeKV(kv_data)


@pytest.mark.parametrize("value, expected", [
    ("192.0.2.24", ("ip", "192.0.2.24")),
    (" 192.0.2.24:443 ", ("ip", "192.0.2.24")),
    ("2001:DB8::1", ("ip", "2001:db8::1")),
    ("[2001:db8::1]", ("ip", "2001:db8::1")),
    ("WWW.Example.COM.", ("domain", "www.example.com")),
    ("https://www.example.com:8443/login?x=1", ("domain", "www.example.com")),
    ("http://192.0.2.24/path", ("ip", "192.0.2.24")),
    ("www.example.com:443", ("domain", "www.example.com")),
    ("www.example.com/path", ("domain", "www.example.com")),
    ("alice@mail.example.com", ("domain", "mail.example.com")),
    (["", "h1.example.com"], ("domain", "h1.example.com")),
    ("localhost", None),
    ("not a host", None),
    ("", None),
    (None, None),
    ("-", None),
])
def test_normalize(value, expected):
    assert normalize(value) == expected


def test_normalize_with_type():
    assert normalize("192.0.2.1", "domain") is None
    assert normalize("example.com", "ip") is None
    assert normalize("192.0.2.1", "ip") == ("ip", "192.0.2.1")


def test_parent_domains():
    assert parent_domains("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]
    assert parent_domains("example.com") == ["example.com"]


def test_worst_grade():
    assert worst_grade(["A", "B", "A+"]) == "B"
    assert worst_grade(["A", "T", "F"]) == "T"
    assert worst_grade(["", None, "Z"]) is None


def test_enrich_known_ip(kv):
    ctx = Enricher(kv).enrich([("ip", "192.0.2.24")])[("ip", "192.0.2.24")]
    assert ctx["known"] == 1 and ctx["in_scope"] == 1
    assert "host" in ctx["asset_type"]
    assert ctx["ip"] == "192.0.2.24"
    assert set(ctx["ports"]) == {22, 80, 443, 3000}
    assert "h278.h279.example.com" in ctx["hostnames"]
    assert ctx["vulnerable"] == 1
    assert ctx["warning"] == 1
    assert "Multiple software vulnerabilities (High)" in ctx["warnings"]
    assert ctx["country"] == ["Germany"]
    assert ctx["first_seen"] <= ctx["last_seen"]


def test_unknown_and_gone_ips(kv):
    out = Enricher(kv).enrich([("ip", "203.0.113.7"), ("ip", "198.51.100.99")])
    for ctx in out.values():
        assert ctx["known"] == 0 and ctx["in_scope"] == 0 and ctx["phishy"] == 0
        assert ctx["ports"] is None


def test_enrich_hostname(kv_data, kv):
    cert = next(r for r in kv_data["shadowtrackr_certificates"] if r.get("url") and r.get("grade"))
    name = cert["url"]
    ctx = Enricher(kv).enrich([("domain", name)])[("domain", name)]
    assert ctx["known"] == 1
    assert "certificate" in ctx["asset_type"]
    assert ctx["cert_grade"] == worst_grade(r.get("grade") for r in kv_data["shadowtrackr_certificates"]
                                            if r.get("url") == name)
    assert ctx["cert_expires"]
    assert ctx["hostnames"] == [name]
    assert ctx["domain"] == "example.com"  # owned parent domain from the domains lookup
    assert ctx["ip"]


def test_cves_per_asset(kv_data, kv):
    cve = next(r for r in kv_data["shadowtrackr_cves"] if r.get("cvss"))
    asset = cve["asset"]
    key = normalize(asset)
    ctx = Enricher(kv).enrich([key])[key]
    expected = {r["cve"] for r in kv_data["shadowtrackr_cves"] if r["asset"] == asset}
    assert set(ctx["cves"]) == expected
    assert ctx["cve_count"] == len(expected)
    assert ctx["max_cvss"] == max(r["cvss"] for r in kv_data["shadowtrackr_cves"]
                                  if r["asset"] == asset and r.get("cvss") is not None)
    assert ctx["vulnerable"] == 1


def test_undiscovered_subdomain_is_in_scope_but_not_known(kv):
    ctx = Enricher(kv).enrich([("domain", "brand-new.example.com")])[("domain", "brand-new.example.com")]
    assert ctx["known"] == 0
    assert ctx["in_scope"] == 1
    assert ctx["domain"] == "example.com"


def test_phishy_domain_and_its_subdomains(kv_data, kv):
    phishy = kv_data["shadowtrackr_phishy_domains"][0]
    sub = "login." + phishy["phishy_domain"]
    out = Enricher(kv).enrich([("domain", phishy["phishy_domain"]), ("domain", sub)])
    for ctx in out.values():
        assert ctx["phishy"] == 1
        assert ctx["lookalike_of"] == [phishy["lookalike_of"]]
        assert ctx["known"] == 0 and ctx["in_scope"] == 0


def test_lookups_are_cached_and_batched(kv):
    enricher = Enricher(kv, batch_size=2)
    keys = [("ip", "192.0.2.{}".format(i)) for i in range(1, 6)]
    enricher.enrich(keys)
    host_calls = [c for c in kv.calls if c[0] == "shadowtrackr_hosts"]
    assert [len(c[2]) for c in host_calls] == [2, 2, 1]

    kv.calls.clear()
    enricher.enrich(keys[:3])
    assert kv.calls == []  # all cached
    enricher.enrich(keys + [("ip", "192.0.2.99")])
    assert {c[2] for c in kv.calls} == {("192.0.2.99",)}


def test_apply_adds_every_field_and_unwraps_single_values(kv):
    ctx = Enricher(kv).enrich([("ip", "192.0.2.24")])[("ip", "192.0.2.24")]
    record = apply({"dest_ip": "192.0.2.24"}, ctx)
    assert [k for k in record if k.startswith("st_")] == ["st_" + f for f in FIELDS]
    assert record["st_country"] == "Germany"
    assert isinstance(record["st_ports"], list)

    empty = apply({"x": 1}, None, prefix="se_")
    assert set(empty) == {"x"} | {"se_" + f for f in FIELDS}
    assert all(v is None for k, v in empty.items() if k != "x")
