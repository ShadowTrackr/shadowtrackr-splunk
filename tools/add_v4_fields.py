#!/usr/bin/env python3
"""Add the v4 API fields (id, asset, changes, organization, ...) to a fixture.

Usage:
  python3 -I tools/add_v4_fields.py tests/fixtures/events.json CURATED.csv OUT_EVENTS.json OUT_EVENT_TYPES.json

The live API did not have these fields yet when the fixtures were made, so
they are derived from the legacy fields following the API team's spec. Replace
the fixtures with redacted live responses once the new API is deployed.
"""

import csv
import json
import random
import re
import sys

ORG_A = {"id": 1470062, "name": "Customer A"}
ORG_B = {"id": 1470063, "name": "Customer B"}
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+:[0-9a-f:]*$", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d+")
CHANGED_RE = re.compile(r"(?:changed )?from (.+?) to (.+?)(?:\.|$)")
GRADE_RES = [
    re.compile(r"Grade: ([A-FMT][+-]?)"),
    re.compile(r"with grade ([A-FMT][+-]?)"),
]


def params(request):
    parts = (request or "").split("&")
    out = {"_head": parts[0] if parts else ""}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k] = v
    return out


def snake(text):
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def enrich(e, rng):
    p = params(e.get("request"))
    msg = e["msg"]
    e["message_text"] = re.sub(r"<br\s*/?>", "\n", msg)

    head = p["_head"] or e.get("dst") or ""
    if head:
        e["asset"] = head
        e["asset_type"] = "ip" if IP_RE.match(head) else "url"
    ip = p.get("ip") or p.get("wip") or (e.get("dst") if e.get("dst") and IP_RE.match(e["dst"]) else None)
    if ip:
        e["ip"] = ip
    if p.get("serial"):
        e["cert_serial"] = p["serial"]
    if p.get("cloudprovider"):
        e["cloud_provider"] = p["cloudprovider"]
    if p.get("serial") is not None and p.get("url"):
        e["link"] = "https://shadowtrackr.com/usr/certificate?ip={}&serial={}&url={}".format(
            p.get("ip", ""), p.get("serial", ""), p["url"])
    elif p.get("wid"):
        e["link"] = "https://shadowtrackr.com/usr/website?wid={}".format(p["wid"])

    cves = sorted(set(CVE_RE.findall(msg)))
    if cves:
        e["cve"] = cves

    if e["source"] == "ssl":
        for rx in GRADE_RES:
            m = rx.search(msg)
            if m:
                e["grade"] = m.group(1)
                break
        else:
            m = re.search(r"Grade capped to ([A-FMT])", e.get("cs1", ""))
            if m:
                e["grade"] = m.group(1)

    if e["eventid"] in (1553, 1559, 1668, 1646):
        m = CHANGED_RE.search(msg)
        if m:
            attribute = {1553: "asn_name", 1559: "bgp_prefix", 1668: "security_grade", 1646: "http_header"}[e["eventid"]]
            old, new = m.group(1).strip(), m.group(2).strip()
            e["changes"] = [{"attribute": attribute, "old_value": old, "new_value": new}]
            e["old_value"], e["new_value"] = old, new
            if e["eventid"] == 1668:
                e["previous_grade"], e["grade"] = old, new

    if e["eventid"] in (281, 282, 283):
        port = rng.choice([(3389, "rdp"), (22, "ssh"), (8080, "http-alt"), (3306, "mysql")])
        state = "opened" if e["eventid"] == 283 else rng.choice(["opened", "closed"])
        e["ports"] = [{"port": port[0], "state": state, "name": port[1]}]
        e["port"] = port[0]

    e["organization"] = ORG_A if rng.random() > 0.2 else ORG_B
    return e


def extra_events(last_ts):
    """Event types that were not in the redacted sample."""
    return [
        {"timestamp": last_ts, "eventid": 218, "level": 91, "source": "hosts",
         "msg": "Port 3389 (rdp) opened on host 192.0.2.19",
         "dst": "192.0.2.19", "port": 3389, "protocol": "tcp"},
        {"timestamp": last_ts, "eventid": 3320, "level": 81, "source": "dns",
         "msg": "DMARC policy for example.com weakened from reject to none",
         "request": "example.com"},
    ]


def main():
    events_path, curated_path, out_events, out_types = sys.argv[1:5]
    rng = random.Random(7)
    with open(events_path, encoding="utf-8") as f:
        events = json.load(f)["data"]
    # Start from the legacy fields only, so the script can be re-run.
    legacy_keys = ("timestamp", "eventid", "level", "source", "msg", "cs1", "request", "dst", "fname")
    events = [{k: e[k] for k in legacy_keys if k in e} for e in events]
    events.sort(key=lambda e: e["timestamp"])
    events += extra_events(events[-1]["timestamp"])
    for e in events[-2:]:
        if e["eventid"] == 218:
            e["asset"], e["asset_type"], e["ip"] = "192.0.2.19", "ip", "192.0.2.19"

    next_id = 1297240000
    for e in events:
        next_id += rng.randint(1, 40)
        e["_order"] = next_id
    # A few late inserts: an older timestamp but a newer row.
    for e in rng.sample(events[:-10], 3):
        next_id += rng.randint(1, 40)
        e["_order"] = next_id

    out = []
    for e in sorted(events, key=lambda e: e["_order"]):
        new_id = e.pop("_order")
        legacy = {k: e[k] for k in legacy_keys if k in e}
        extra = {k: v for k, v in e.items() if k not in legacy_keys}
        record = dict(legacy, id=new_id, **extra)
        out.append(enrich(record, rng) if record["eventid"] not in (218, 3320) else
                   dict(record, message_text=record["msg"], organization=ORG_A,
                        **({"asset": "example.com", "asset_type": "url", "changes": [
                            {"attribute": "dmarc_policy", "old_value": "reject", "new_value": "none"}],
                            "old_value": "reject", "new_value": "none"} if record["eventid"] == 3320 else {})))
    with open(out_events, "w", encoding="utf-8") as f:
        json.dump({"results": "{} results found".format(len(out)), "error": "", "data": out}, f, indent=2)
        f.write("\n")

    types = []
    with open(curated_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            category = row["st_category"]
            types.append({
                "eventid": int(row["eventid"]), "source": row["source"], "name": snake(row["signature"]),
                "category": category, "default_level": None, "is_change": row["st_cim_type"] == "change",
            })
    types = [t for t in types if t["eventid"] != 1415]
    types += [
        {"eventid": 1415, "source": "ssl", "name": "ssllabs_renewed_cert_problems", "category": "certificate",
         "default_level": 91, "is_change": True},
        {"eventid": 218, "source": "ports", "name": "port_opened", "category": "host",
         "default_level": None, "is_change": True},
        {"eventid": 219, "source": "ports", "name": "port_closed", "category": "host",
         "default_level": None, "is_change": True, "aliases": ["port_removed"]},
        {"eventid": 3320, "source": "dns", "name": "dmarc_policy_weakened", "category": "dns",
         "default_level": 81, "is_change": True},
    ]
    types.sort(key=lambda t: t["eventid"])
    with open(out_types, "w", encoding="utf-8") as f:
        json.dump({"results": "{} results found".format(len(types)), "error": "", "data": types}, f, indent=2)
        f.write("\n")
    print("wrote {} events, {} event types".format(len(out), len(types)), file=sys.stderr)


if __name__ == "__main__":
    main()
