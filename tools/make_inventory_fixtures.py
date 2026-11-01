#!/usr/bin/env python3
"""Build redacted inventory fixtures from raw API responses.

Usage:
  python3 -I tools/make_inventory_fixtures.py RAW_DIR tests/fixtures/inventory [--sample 25]

RAW_DIR holds one raw response per endpoint (<endpoint>.json), saved outside
the repository. For each endpoint this takes an evenly spread sample, drops
fields that may hold site secrets or tracking ids (raw HTTP headers, analytics
ids, fingerprints), shortens long lists and redacts the rest with
redact_events.Redactor. Review the output before committing.
"""

import argparse
import collections
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from redact_events import HOST_RE, Redactor, registered_domain  # noqa: E402

DROP_FIELDS = {
    "http_headers", "https_headers", "external_scripts", "external_css", "http_redirect_history",
    "https_redirect_history", "google_analytics_id", "meta_pixel_id", "jarm", "mmh3", "pinsha256",
    "sha1hash", "cryptographic_suites", "http_cookie_on_load", "https_cookie_on_load", "description",
    "http_ssdeep", "https_ssdeep", "http_response", "https_response",
}
MAX_LIST = 8


def trim(value, key=None):
    if isinstance(value, dict):
        return {k: trim(v, k) for k, v in value.items() if k not in DROP_FIELDS}
    if isinstance(value, list):
        return [trim(v) for v in value[:MAX_LIST]]
    return value


def sample(records, n):
    if len(records) <= n:
        return records
    step = len(records) / n
    return [records[int(i * step)] for i in range(n)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_dir")
    parser.add_argument("out_dir")
    parser.add_argument("--sample", type=int, default=25)
    args = parser.parse_args()

    raw = {}
    for name in sorted(os.listdir(args.raw_dir)):
        if name.endswith(".json"):
            with open(os.path.join(args.raw_dir, name), encoding="utf-8") as f:
                data = json.load(f).get("data")
            if isinstance(data, list):
                raw[name[:-5]] = data

    # One redactor for all endpoints, so the same host maps to the same
    # placeholder everywhere (hosts, websites and certificates stay joinable).
    hosts = collections.Counter()
    for records in raw.values():
        for m in HOST_RE.finditer(json.dumps(records)):
            hosts[registered_domain(m.group(0))] += 1
    redactor = Redactor(hosts.most_common(1)[0][0] if hosts else "example.com", random.Random(1))

    os.makedirs(args.out_dir, exist_ok=True)
    for endpoint, records in raw.items():
        rows = [redactor.event(trim(r)) for r in sample(records, args.sample)]
        with open(os.path.join(args.out_dir, endpoint + ".json"), "w", encoding="utf-8") as f:
            json.dump({"results": "{} results found".format(len(rows)), "error": "", "data": rows}, f, indent=2)
            f.write("\n")
        print("{:24} {:5} -> {:3}".format(endpoint, len(records), len(rows)), file=sys.stderr)


if __name__ == "__main__":
    main()
