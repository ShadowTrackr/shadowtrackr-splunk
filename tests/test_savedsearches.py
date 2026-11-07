"""Checks on the generated detections (package/default/savedsearches.conf)."""

import csv
import json
import os
import re
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(ROOT, "package", "default")
sys.path.insert(0, os.path.join(ROOT, "tools"))

import gen_savedsearches  # noqa: E402


def parse_conf(path):
    """{stanza: {key: value}} with backslash line continuations joined."""
    stanzas, current, pending = {}, None, None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if pending is not None:
                key, value = pending
                value += "\n" + line
            else:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                if line.startswith("["):
                    current = stanzas.setdefault(line.strip()[1:-1], {})
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip()
            if value.endswith("\\"):
                pending = (key, value[:-1])
                continue
            pending = None
            current[key] = value
    return stanzas


SAVED = parse_conf(os.path.join(DEFAULT, "savedsearches.conf"))
MACROS = parse_conf(os.path.join(DEFAULT, "macros.conf"))
TRANSFORMS = parse_conf(os.path.join(DEFAULT, "transforms.conf"))
RULES = {name: s for name, s in SAVED.items() if name.endswith(" - Rule")}
ALERTS = {name: s for name, s in SAVED.items() if "alert.suppress" in s}


def output_fields(search):
    """The columns of the search's last table command."""
    tables = re.findall(r"\|\s*table\s+([^|]+)$", search.strip())
    assert tables, "the search should end with a table command"
    return set(tables[-1].split())


def tokens(text):
    return set(re.findall(r"\$([A-Za-z_][\w.]*)\$", text)) - {"info_min_time", "info_max_time"}


def test_conf_is_up_to_date():
    with open(os.path.join(DEFAULT, "savedsearches.conf"), encoding="utf-8") as f:
        assert f.read() == gen_savedsearches.build(), "run `make savedsearches`"


def test_everything_ships_disabled():
    assert SAVED
    assert all(s.get("disabled") == "1" for s in SAVED.values())


def test_every_detection_has_an_es_rule_with_the_same_search():
    for d in gen_savedsearches.DETECTIONS:
        plain = SAVED["ShadowTrackr - " + d["name"]]
        rule = SAVED["ShadowTrackr - {} - Rule".format(d["name"])]
        assert plain["search"] == rule["search"]
        assert "action.notable" not in plain and "action.risk" not in plain


def test_es_rules_are_complete():
    assert len(RULES) == len(gen_savedsearches.DETECTIONS)
    for name, s in RULES.items():
        assert s["action.correlationsearch.enabled"] == "1"
        assert s["action.correlationsearch.label"] == name
        assert s["action.notable"] == "1" and s["action.risk"] == "1"
        assert s["action.notable.param.security_domain"] in ("access", "endpoint", "network", "threat", "identity",
                                                            "audit")
        assert s["action.notable.param.severity"] in ("informational", "low", "medium", "high", "critical")
        annotations = json.loads(s["action.correlationsearch.annotations"])
        for technique in annotations.get("mitre_attack", []):
            assert re.match(r"^T\d{4}(\.\d{3})?$", technique)
        for entry in json.loads(s["action.risk.param._risk"]):
            if "risk_object_field" in entry:
                assert entry["risk_object_type"] in ("system", "user", "other")
                assert 0 < entry["risk_score"] <= 100
            else:
                assert entry["threat_object_field"] and entry["threat_object_type"]


def test_tokens_and_throttle_fields_are_in_the_results():
    for name, s in ALERTS.items():
        fields = output_fields(s["search"])
        throttle = set(s["alert.suppress.fields"].split(","))
        assert throttle <= fields, (name, throttle - fields)
        if name in RULES:
            used = set()
            for key in ("action.notable.param.rule_title", "action.notable.param.rule_description",
                        "action.risk.param._risk_message", "action.notable.param.drilldown_name",
                        "action.notable.param.drilldown_search"):
                used |= tokens(s[key])
            for entry in json.loads(s["action.risk.param._risk"]):
                used.add(entry.get("risk_object_field") or entry["threat_object_field"])
            used |= set(s["action.notable.param.nes_fields"].split(","))
            assert used <= fields, (name, used - fields)


def test_macros_and_lookups_exist():
    for name, s in SAVED.items():
        search = s["search"]
        for macro in re.findall(r"`([\w]+)`", search):
            assert macro in MACROS, (name, macro)
        for lookup in re.findall(r"\b(?:inputlookup|outputlookup|lookup)\s+([\w]+)", search):
            assert lookup in TRANSFORMS, (name, lookup)


@pytest.mark.parametrize("name", ["shadowtrackr_risky_ports.csv", "shadowtrackr_es_assets.csv"])
def test_lookup_files(name):
    with open(os.path.join(ROOT, "package", "lookups", name), encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if name == "shadowtrackr_risky_ports.csv":
        ports = [int(r["port"]) for r in rows]
        assert len(ports) == len(set(ports))
        assert all(r["service"] and r["reason"] for r in rows)
        assert 3389 in ports and 22 not in ports


def test_es_asset_lookup_columns():
    search = SAVED["ShadowTrackr - ES asset lookup - Lookup Gen"]["search"]
    with open(os.path.join(ROOT, "package", "lookups", "shadowtrackr_es_assets.csv"), encoding="utf-8") as f:
        header = f.readline().strip().split(",")
    assert header == gen_savedsearches.ES_ASSET_FIELDS.split()
    assert search.rstrip().endswith("outputlookup shadowtrackr_es_assets")
