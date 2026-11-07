#!/usr/bin/env python3
"""Send synthetic ShadowTrackr alert webhook deliveries through HEC and check how Splunk parses them.

Usage: python3 -I tools/send_webhook_test.py [--index shadowtrackr] [--no-verify]

Reads tests/fixtures/webhook_alerts.json, posts it to the dev Splunk's HTTP
Event Collector the way ShadowTrackr does (sourcetype shadowtrackr:alert),
then searches for it and checks the field extractions (dest, severity,
vendor_account), the retry dedupe (st_result_key) and that the truncation
marker is left out of the shadowtrackr_webhook_alert event type.

Each run gets fresh delivery ids, so runs never mix. Needs SPLUNK_HEC_TOKEN
and SPLUNK_PASSWORD (from .env) and the dev Splunk on localhost.
"""

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "webhook_alerts.json")
HEC = "https://localhost:8088/services/collector/event"
MGMT = "https://localhost:8089"
CTX = ssl._create_unverified_context()  # the dev Splunk has a self-signed certificate


def load_env():
    path = os.path.join(ROOT, ".env")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                key, sep, value = line.strip().partition("=")
                if sep and not key.startswith("#"):
                    os.environ.setdefault(key, value)


def send(index, run):
    with open(FIXTURE, encoding="utf-8") as f:
        fixture = json.load(f)
    now = time.time()
    events = []
    for item in fixture["data"]:
        item = dict(item, delivery_id="{}-{}".format(item["delivery_id"], run))
        events.append({"time": now, "index": index, "sourcetype": "shadowtrackr:alert",
                       "source": "shadowtrackr:webhook-test", "event": item})
    body = "\n".join(json.dumps(e) for e in events).encode()
    req = urllib.request.Request(HEC, data=body, headers={"Authorization": "Splunk " + os.environ["SPLUNK_HEC_TOKEN"]})
    with urllib.request.urlopen(req, context=CTX, timeout=30) as resp:
        print("HEC:", resp.read().decode())
    return fixture["expected"]


def search(query):
    auth = base64.b64encode(("admin:" + os.environ["SPLUNK_PASSWORD"]).encode()).decode()
    data = urllib.parse.urlencode({"search": query, "exec_mode": "oneshot", "output_mode": "json", "count": 0,
                                   "earliest_time": "-1h", "latest_time": "+1m"}).encode()
    req = urllib.request.Request(MGMT + "/servicesNS/admin/shadowtrackr/search/jobs", data=data,
                                 headers={"Authorization": "Basic " + auth})
    with urllib.request.urlopen(req, context=CTX, timeout=120) as resp:
        return json.load(resp).get("results", [])


def verify(index, run, expected):
    base = 'search index={} sourcetype="shadowtrackr:alert" delivery_id="*-{}"'.format(index, run)
    rows = []
    for _ in range(20):  # indexing takes a moment
        rows = search(base + " | stats count")
        if rows and int(rows[0]["count"]) >= expected["events"]:
            break
        time.sleep(1)
    problems = []
    count = int(rows[0]["count"]) if rows else 0
    if count != expected["events"]:
        problems.append("expected {} events, found {}".format(expected["events"], count))
    results = search(base + " eventtype=shadowtrackr_webhook_alert | dedup st_result_key"
                     " | eval key=alert_id.\":\".result_index | table key dest severity vendor_account tag")
    if len(results) != expected["results"]:
        problems.append("expected {} results after dedupe, found {}".format(expected["results"], len(results)))
    by_key = {r["key"]: r for r in results}
    for field in ("dest", "severity", "vendor_account"):
        for key, value in expected[field].items():
            got = by_key.get(key, {}).get(field)
            if got != value:
                problems.append("{} {}: expected {!r}, got {!r}".format(key, field, value, got))
    if any("alert" not in (r.get("tag") if isinstance(r.get("tag"), list) else [r.get("tag")]) for r in results):
        problems.append("results should carry the alert tag")
    for r in sorted(results, key=lambda r: r["key"]):
        print("  {key:8s} dest={dest:18s} severity={severity:8s} vendor_account={va}".format(
            va=r.get("vendor_account"), **r))
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--index", default="shadowtrackr")
    parser.add_argument("--no-verify", action="store_true")
    args = parser.parse_args()
    load_env()
    run = uuid.uuid4().hex[:8]
    expected = send(args.index, run)
    if args.no_verify:
        return 0
    problems = verify(args.index, run, expected)
    for p in problems:
        print("FAIL:", p)
    print("OK" if not problems else "{} problem(s)".format(len(problems)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
