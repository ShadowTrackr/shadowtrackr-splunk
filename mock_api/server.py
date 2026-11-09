#!/usr/bin/env python3
"""Mock ShadowTrackr v4 API serving redacted fixtures.

By default it implements the v4 API as specified by the ShadowTrackr team
(since_id paging, structured fields, /event_types, status codes, group keys).
With --legacy it behaves like the API before those changes, so the app's
fallback to time windows stays testable.

v4 behaviour:
  * POST /api/v4/<endpoint>, "Authorization: Bearer <key>"
  * 401 for a missing or unknown key, 403 without API access or for an
    organization outside the group, 400 for parameters that are not allowed,
    JSON 404 for unknown endpoints (live still answers HTML until nginx is
    updated; the client handles both)
  * events:
      since_id/limit  ids > since_id ascending, limit default 1000, max 5000,
                      next_since_id and latest_id in the envelope
      limit only      the newest N, newest first, plus latest_id
      start + stop    the inclusive window, grouped by (source, eventid)
      start only      everything from start, grouped the same way
      no parameters   the newest 1000, newest first
      min_level       level greater than the value
      level_gte       level greater than or equal to the value
      organization_id group keys only
  * events carry organization only for group keys (as on live)
  * event_types with optional category / source / eventid filters
  * organizations for group keys (a normal key gets HTTP 200 with an error)
  * inventory list endpoints (hosts, websites, ...) from tests/fixtures/inventory;
    a group key must pass organization_id, Customer B gets a small slice
  * query: {"q": "..."} with a small subset of the GUI query language:
    index=<name> (or <index>.<field>:), field=value / field:value with *
    wildcards, != > < >= <=, "by <field>" (count per value) and
    "| table a b"; earliest/latest are accepted and ignored. Rows are
    flattened like on live (lists become comma-separated strings). A group
    key may pass organization_id, as on the list endpoints.

Legacy behaviour (--legacy): no ids or new fields, since_id ignored, a wrong
key gives HTTP 200 with an "error", unknown endpoints give an HTML 404.

API keys:
  mock-api-key-0000000000    organization "Customer A"
  mock-group-key-000000000   Group read-only key for "Customer A" and "Customer B":
                             lists its organizations, but asking for their keys
                             with a groupcode is refused (403 insufficient_scope)
  mock-no-api-access         valid key without API access (403)
  mock-expired-key           expired scoped key (401 "API key expired")
  mock-ip-not-allowed        request from outside the key's IP allowlist (403)
  mock-error-500 / mock-error-429 / mock-error-slow / mock-error-html
                             fault injection

For live testing, POST /_mock/insert (no auth) with an event body appends it
with the next id, e.g. to simulate a late insert with an old timestamp.

Usage:
  python3 mock_api/server.py [--port 8081] [--shift-to-now] [--legacy]
"""

import argparse
import copy
import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures")
DEFAULT_API_KEY = "mock-api-key-0000000000"
GROUP_API_KEY = "mock-group-key-000000000"
NO_ACCESS_KEY = "mock-no-api-access"
EXPIRED_KEY = "mock-expired-key"
IP_NOT_ALLOWED_KEY = "mock-ip-not-allowed"
API_PREFIX = "/api/v4/"
EVENTS_DEFAULT_LIMIT = 1000
EVENTS_MAX_LIMIT = 5000

ORGANIZATIONS = [{"oid": 1470062, "name": "Customer A", "custom_id": ""},
                 {"oid": 1470063, "name": "Customer B", "custom_id": ""}]
KEY_ORGS = {DEFAULT_API_KEY: {1470062}, GROUP_API_KEY: {1470062, 1470063}}

LEGACY_KEYS = ("timestamp", "eventid", "level", "source", "msg", "cs1", "request", "dst", "fname")
EVENT_PARAMS = {"since_id", "limit", "start", "stop", "update_only", "updates_only", "update",
                "output_format", "min_level", "level_gte", "organization_id", "api_key"}

NOT_FOUND_HTML = b"<!DOCTYPE html><html><head><title>404 Page not found</title></head><body>Not found</body></html>"


class BadRequest(Exception):
    pass


def _parse_ts(value):
    text = str(value).strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1]
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def _fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return json.load(f)["data"]


INVENTORY_ENDPOINTS = (
    "hosts", "websites", "urls", "domains", "subnets", "certificates", "dns", "mailservers", "software",
    "vulnerabilities", "cves_assets", "cloud_providers", "remote_login_services", "blacklisted_assets",
    "exposed_email_addresses", "suggestions", "phishy_domains", "suppliers", "internet_standards",
)


def load_inventory():
    inventory = {}
    for endpoint in INVENTORY_ENDPOINTS:
        try:
            inventory[endpoint] = _load(os.path.join("inventory", endpoint + ".json"))
        except FileNotFoundError:
            inventory[endpoint] = []
    return inventory


def load_events(shift_to_now=False, legacy=False):
    events = _load("events.json")
    if shift_to_now and events:
        newest = max(_parse_ts(e["timestamp"]) for e in events)
        delta = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=5) - newest
        for e in events:
            e["timestamp"] = _fmt_ts(_parse_ts(e["timestamp"]) + delta)
    if legacy:
        events = [{k: e[k] for k in LEGACY_KEYS if k in e} for e in events]
    return events


def _grouped(events):
    return sorted(events, key=lambda e: (e["source"], e["eventid"], e["timestamp"]))


def filter_events(events, body):
    """Select events like the API does for start/stop or no parameters."""
    start, stop = body.get("start"), body.get("stop")
    if start and stop:
        try:
            lo, hi = _parse_ts(start), _parse_ts(stop)
        except ValueError:
            lo = hi = None
        if lo is not None:
            return _grouped([e for e in events if lo <= _parse_ts(e["timestamp"]) <= hi])
    if start and not stop:
        try:
            lo = _parse_ts(start)
            return _grouped([e for e in events if _parse_ts(e["timestamp"]) >= lo])
        except ValueError:
            pass
    newest = sorted(events, key=lambda e: e["timestamp"], reverse=True)
    return newest[:EVENTS_DEFAULT_LIMIT]


def page_events(events, since_id, limit):
    """since_id paging: ids above since_id, ascending, at most limit."""
    page = sorted((e for e in events if e["id"] > since_id), key=lambda e: e["id"])[:limit]
    return page, (page[-1]["id"] if page else since_id)


def _int_param(body, name, default=None, minimum=None):
    if name not in body:
        return default
    value = body[name]
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int) or (minimum is not None and value < minimum):
        raise BadRequest("Invalid value for {}".format(name))
    return value


# Query index names (singular or plural) and the fixture they read.
QUERY_INDEXES = {
    "hosts": "hosts", "websites": "websites", "urls": "urls", "domains": "domains", "certificates": "certificates",
    "dns": "dns", "suggestions": "suggestions", "emails": "exposed_email_addresses",
    "vulnerabilities": "vulnerabilities", "phishy_domains": "phishy_domains", "events": "events",
    "suppliers": "suppliers",
}
_QUERY_TERM = re.compile(r'([\w.]+)\s*(!=|>=|<=|=>|=|:|>|<)\s*("[^"]*"|\S+)')


def _query_index(name):
    name = name.lower()
    if name in QUERY_INDEXES:
        return name
    if name + "s" in QUERY_INDEXES:
        return name + "s"
    return None


def flatten_query_row(row):
    """A fixture row the way /query returns it: flat, lists as comma-separated strings."""
    flat = {}
    for key, value in row.items():
        if isinstance(value, list):
            if all(isinstance(v, (str, int, float, bool)) for v in value):
                flat[key] = ",".join(str(v) for v in value)
        elif not isinstance(value, dict):
            flat[key] = value
    for proto in ("tcp", "udp"):
        if isinstance(row.get(proto), list):
            flat[proto + "_ports"] = ",".join(str(p.get("port")) for p in row[proto] if isinstance(p, dict))
    return flat


def _matches(value, op, wanted):
    if value is None:
        return op == "!="
    if op in (">", "<", ">=", "<=", "=>"):
        try:
            a, b = float(value), float(wanted)
        except (TypeError, ValueError):
            a, b = str(value), wanted
        return {">": a > b, "<": a < b, ">=": a >= b, "=>": a >= b, "<=": a <= b}[op]
    if isinstance(value, bool):
        value = "yes" if value else "no"
        wanted = {"true": "yes", "1": "yes", "false": "no", "0": "no"}.get(wanted.lower(), wanted.lower())
    pattern = "^" + ".*".join(re.escape(part) for part in wanted.lower().split("*")) + "$"
    hit = any(re.match(pattern, part.strip()) for part in str(value).lower().split(","))
    return not hit if op == "!=" else hit


def run_mock_query(q, data_for):
    """Rows for a query. data_for(index) returns the flattened rows of an index."""
    q, _, pipe = q.partition("|")
    table = pipe.split()[1:] if pipe.strip().lower().startswith("table") else None
    by = None
    match = re.search(r"\bby\s+([\w.]+)", q)
    if match:
        by = match.group(1)
        q = q[:match.start()] + q[match.end():]
    index, filters = None, []
    for field, op, value in _QUERY_TERM.findall(q):
        value = value.strip('"')
        if field.lower() == "index":
            index = _query_index(value.split(".")[0])
            continue
        if field.lower() in ("earliest", "latest", "include_ignored"):
            continue
        if "." in field:
            prefix, field = field.split(".", 1)
            index = index or _query_index(prefix)
        filters.append((field, "=" if op == ":" else op, value))
    if index is None:
        return []
    rows = [r for r in data_for(index) if all(_matches(r.get(f), op, v) for f, op, v in filters)]
    if by:
        counts = {}
        for r in rows:
            counts[r.get(by)] = counts.get(r.get(by), 0) + 1
        return [{by: k, "count": n} for k, n in sorted(counts.items(), key=lambda kv: -kv[1])]
    if table:
        rows = [{f: r.get(f) for f in table} for r in rows]
    return rows


def org_for(event):
    """The fixtures come from one organization; spread them over two for the group key."""
    return ORGANIZATIONS[1] if event.get("id", 0) % 5 == 0 else ORGANIZATIONS[0]


class MockAPI:
    def __init__(self, events, event_types, legacy=False, inventory=None):
        self.events = events
        self.event_types = event_types
        self.inventory = inventory if inventory is not None else load_inventory()
        self.legacy = legacy
        self.lock = threading.Lock()

    def insert(self, event):
        with self.lock:
            event = dict(event)
            if not self.legacy:
                event["id"] = max([e.get("id", 0) for e in self.events] + [0]) + 1
            event.setdefault("timestamp", _fmt_ts(datetime.now(timezone.utc)))
            self.events.append(event)
            return event

    def events_for(self, key, body):
        """Events visible to a key. Only group keys get an organization field."""
        orgs = KEY_ORGS.get(key, set())
        if "organization_id" in body:
            org_id = _int_param(body, "organization_id")
            if key != GROUP_API_KEY:
                raise BadRequest("organization_id requires a group key")
            if org_id not in orgs:
                return 403, "Organization not in this group"
            orgs = {org_id}
        with self.lock:
            visible = [e for e in self.events if org_for(e)["oid"] in orgs]
        if key == GROUP_API_KEY:
            visible = [dict(e, organization={"id": org_for(e)["oid"], "name": org_for(e)["name"]}) for e in visible]
        return 200, visible


def make_handler(api, api_key):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ShadowTrackrMock/2.0"

        def log_message(self, fmt, *args):
            sys.stderr.write("[mock] %s\n" % (fmt % args))

        def _send(self, status, payload=None, raw=None, content_type="application/json"):
            body = raw if raw is not None else json.dumps(payload, indent=4).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _envelope(self, data=None, error="", **extra):
            data = data if data is not None else []
            results = "" if error else "{} results found".format(len(data))
            return dict({"results": results, "error": error, "data": data}, **extra)

        def _error(self, status, message):
            if api.legacy and status != 401:
                # The legacy API answers most errors with HTTP 200.
                return self._send(200, self._envelope(error=message))
            if api.legacy and message == "Invalid API key":
                return self._send(200, self._envelope(error=message))
            return self._send(status, self._envelope(error=message))

        def _not_found(self):
            if api.legacy:
                return self._send(404, raw=NOT_FOUND_HTML, content_type="text/html")
            return self._send(404, self._envelope(error="Unknown endpoint"))

        def do_GET(self):
            self._not_found()

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            except ValueError:
                body = {}
            if not isinstance(body, dict):
                body = {}

            if self.path == "/_mock/insert":
                return self._send(200, api.insert(body))
            if not self.path.startswith(API_PREFIX):
                return self._not_found()
            endpoint = self.path[len(API_PREFIX):].strip("/")

            auth = self.headers.get("Authorization", "")
            key = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if not key:
                return self._send(401, self._envelope(error="Unauthorized. No API key provided"))
            if key == "mock-error-500":
                return self._send(500, raw=b"Internal Server Error", content_type="text/plain")
            if key == "mock-error-429":
                self.send_response(429)
                self.send_header("Retry-After", "1")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            if key == "mock-error-html":
                return self._send(200, raw=NOT_FOUND_HTML, content_type="text/html")
            if key == "mock-error-slow":
                time.sleep(3)
                key = DEFAULT_API_KEY
            if key == NO_ACCESS_KEY:
                return self._error(403, "API access is not enabled for this account")
            if key == EXPIRED_KEY:
                return self._error(401, "API key expired")
            if key == IP_NOT_ALLOWED_KEY:
                return self._error(403, "Request not allowed from this IP address")
            if key == api_key and key not in KEY_ORGS:
                key = DEFAULT_API_KEY
            if key not in KEY_ORGS:
                return self._error(401, "Invalid API key")

            try:
                if endpoint == "events":
                    return self._events(key, body)
                if endpoint == "event_types" and not api.legacy:
                    return self._event_types(body)
                if endpoint == "organizations" and not api.legacy:
                    if key != GROUP_API_KEY:
                        # As on live: HTTP 200 with an error for a normal key.
                        return self._send(200, self._envelope(error="Error: No groupcode provided"))
                    if "groupcode" in body:
                        # The organizations' keys and admin codes need group_admin.
                        return self._error(403, "insufficient_scope")
                    return self._send(200, {"results": "2 Organizations found", "error": "",
                                            "data": {"active_organizations": 2, "organizations": ORGANIZATIONS}})
                if endpoint in INVENTORY_ENDPOINTS:
                    return self._inventory(key, endpoint, body)
                if endpoint == "query" and not api.legacy:
                    return self._query(key, body)
            except BadRequest as e:
                return self._error(400, str(e))
            return self._not_found()

        def _events(self, key, body):
            if api.legacy:
                with api.lock:
                    events = list(api.events)
                return self._send(200, self._envelope(filter_events(events, body)))

            unknown = set(body) - EVENT_PARAMS
            if unknown:
                raise BadRequest("Unknown parameter: {}".format(", ".join(sorted(unknown))))
            if key == GROUP_API_KEY and any(k in body for k in ("update_only", "updates_only", "update")):
                raise BadRequest("update_only is not supported for group keys, use since_id")
            status, events = api.events_for(key, body)
            if status != 200:
                return self._error(status, events)
            # latest_id covers every level the key can see, before level filters.
            latest_id = max([e["id"] for e in events] + [0])
            min_level = _int_param(body, "min_level")
            if min_level is not None:
                events = [e for e in events if e["level"] > min_level]
            level_gte = _int_param(body, "level_gte")
            if level_gte is not None:
                events = [e for e in events if e["level"] >= level_gte]
            limit = min(_int_param(body, "limit", EVENTS_DEFAULT_LIMIT, minimum=1), EVENTS_MAX_LIMIT)
            if "since_id" in body:
                since_id = _int_param(body, "since_id", minimum=0)
                page, next_since_id = page_events(events, since_id, limit)
                return self._send(200, self._envelope(page, next_since_id=next_since_id, latest_id=latest_id))
            if "limit" in body and not (body.get("start") or body.get("stop")):
                newest = sorted(events, key=lambda e: e["timestamp"], reverse=True)[:limit]
                return self._send(200, self._envelope(newest, latest_id=latest_id))
            return self._send(200, self._envelope(filter_events(events, body)))

        def _inventory(self, key, endpoint, body):
            """List endpoints. A group key must name an organization_id (else no data, as on live)."""
            rows = api.inventory.get(endpoint, [])
            if key != GROUP_API_KEY:
                return self._send(200, self._envelope(rows))
            if "organization_id" not in body:
                return self._send(200, self._envelope([]))
            org_id = _int_param(body, "organization_id")
            org = next((o for o in ORGANIZATIONS if o["oid"] == org_id), None)
            if org is None:
                return self._error(403, "Organization not in this group")
            # Customer B gets a small slice of the same fixtures.
            rows = rows if org is ORGANIZATIONS[0] else rows[:3]
            return self._send(200, self._envelope(rows, organization={"id": org["oid"], "name": org["name"]}))

        def _query(self, key, body):
            q = body.get("q")
            if not isinstance(q, str) or not q.strip():
                raise BadRequest("Missing parameter: q")
            org = None
            if "organization_id" in body:
                org_id = _int_param(body, "organization_id")
                if key != GROUP_API_KEY:
                    raise BadRequest("organization_id requires a group key")
                org = next((o for o in ORGANIZATIONS if o["oid"] == org_id), None)
                if org is None:
                    return self._error(403, "Organization not in this group")

            def data_for(index):
                if index == "events":
                    status, events = api.events_for(key, {"organization_id": org["oid"]} if org else {})
                    rows = [dict(flatten_query_row(e), created=e.get("timestamp")) for e in events]
                else:
                    rows = [flatten_query_row(r) for r in api.inventory.get(QUERY_INDEXES[index], [])]
                    if org is ORGANIZATIONS[1]:
                        rows = rows[:3]  # Customer B gets a small slice, as on the list endpoints
                if key == GROUP_API_KEY:
                    name = org["name"] if org else ORGANIZATIONS[0]["name"]
                    rows = [dict(r, organization=r.get("organization") or name) for r in rows]
                return rows

            return self._send(200, self._envelope(run_mock_query(q, data_for)))

        def _event_types(self, body):
            rows = api.event_types
            for field in ("category", "source", "eventid"):
                if field in body:
                    wanted = str(body[field]).lower()
                    rows = [r for r in rows if str(r.get(field, "")).lower() == wanted]
            return self._send(200, self._envelope(rows))

    return Handler


class MockServer(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer.server_bind() does a reverse DNS lookup (getfqdn) that
        # can stall for a long time on some machines. We don't need it.
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.server_name, self.server_port = self.server_address[:2]


def make_server(host="127.0.0.1", port=8081, api_key=DEFAULT_API_KEY, shift_to_now=False, legacy=False):
    api = MockAPI(load_events(shift_to_now, legacy), copy.deepcopy(_load("event_types.json")), legacy)
    server = MockServer((host, port), make_handler(api, api_key))
    server.api = api
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0, reachable from Docker)")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--api-key", default=os.environ.get("MOCK_API_KEY", DEFAULT_API_KEY))
    parser.add_argument("--shift-to-now", action="store_true", help="move fixture timestamps up to now")
    parser.add_argument("--legacy", action="store_true", help="behave like the API before since_id paging")
    args = parser.parse_args()

    server = make_server(args.host, args.port, args.api_key, args.shift_to_now, args.legacy)
    print("Mock ShadowTrackr API{} on http://{}:{}{}  (API key: {}, group key: {})".format(
        " (legacy)" if args.legacy else "", args.host, args.port, API_PREFIX, args.api_key, GROUP_API_KEY), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
