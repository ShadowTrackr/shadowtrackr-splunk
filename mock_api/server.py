#!/usr/bin/env python3
"""Mock ShadowTrackr v4 API serving redacted fixtures.

It mimics the behaviour of the real API as observed in testing:
  * POST /api/v4/<endpoint> with "Authorization: Bearer <key>"
  * no key -> HTTP 401, wrong key -> HTTP 200 with an "error" field
  * unknown endpoints -> HTML 404 page
  * events: without start/stop the newest 1000, newest first; with start and
    stop every event in the inclusive window, grouped by (source, eventid)
    and sorted by time within each group

Fault injection, for testing error handling, by API key:
  mock-error-500   -> HTTP 500
  mock-error-429   -> HTTP 429
  mock-error-slow  -> sleeps 10 seconds before answering
  mock-error-html  -> HTTP 200 with an HTML body

Usage:
  python3 mock_api/server.py [--port 8081] [--api-key KEY] [--shift-to-now]

--shift-to-now moves all fixture timestamps so the newest event is a few
minutes old, which makes the fixtures useful for a live Splunk demo.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures")
DEFAULT_API_KEY = "mock-api-key-0000000000"
API_PREFIX = "/api/v4/"
EVENTS_DEFAULT_LIMIT = 1000

NOT_FOUND_HTML = b"<!DOCTYPE html><html><head><title>404 Page not found</title></head><body>Not found</body></html>"


def _parse_ts(value):
    text = str(value).strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1]
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def _fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_events(shift_to_now=False):
    with open(os.path.join(FIXTURES, "events.json"), encoding="utf-8") as f:
        events = json.load(f)["data"]
    if shift_to_now and events:
        newest = max(_parse_ts(e["timestamp"]) for e in events)
        delta = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=5) - newest
        for e in events:
            e["timestamp"] = _fmt_ts(_parse_ts(e["timestamp"]) + delta)
    return events


def filter_events(events, body):
    start, stop = body.get("start"), body.get("stop")
    if start and stop:
        try:
            lo, hi = _parse_ts(start), _parse_ts(stop)
        except ValueError:
            lo = hi = None
        if lo is not None:
            selected = [e for e in events if lo <= _parse_ts(e["timestamp"]) <= hi]
            return sorted(selected, key=lambda e: (e["source"], e["eventid"], e["timestamp"]))
    if start and not stop:
        try:
            lo = _parse_ts(start)
            selected = [e for e in events if _parse_ts(e["timestamp"]) >= lo]
            return sorted(selected, key=lambda e: (e["source"], e["eventid"], e["timestamp"]))
        except ValueError:
            pass
    newest = sorted(events, key=lambda e: e["timestamp"], reverse=True)
    return newest[:EVENTS_DEFAULT_LIMIT]


def make_handler(api_key, events):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ShadowTrackrMock/1.0"

        def log_message(self, fmt, *args):
            sys.stderr.write("[mock] %s\n" % (fmt % args))

        def _send(self, status, payload=None, raw=None, content_type="application/json"):
            body = raw if raw is not None else json.dumps(payload, indent=4).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _envelope(self, data=None, error=""):
            data = data or []
            results = "" if error else "{} results found".format(len(data))
            return {"results": results, "error": error, "data": data}

        def do_GET(self):
            self._send(404, raw=NOT_FOUND_HTML, content_type="text/html")

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length) if length else b""

            if not self.path.startswith(API_PREFIX):
                return self._send(404, raw=NOT_FOUND_HTML, content_type="text/html")
            endpoint = self.path[len(API_PREFIX):].strip("/")

            auth = self.headers.get("Authorization", "")
            key = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            if not key:
                return self._send(401, self._envelope(error="Unauthorized. No API key provided"))
            if key == "mock-error-500":
                return self._send(500, raw=b"Internal Server Error", content_type="text/plain")
            if key == "mock-error-429":
                return self._send(429, raw=b"Too Many Requests", content_type="text/plain")
            if key == "mock-error-html":
                return self._send(200, raw=NOT_FOUND_HTML, content_type="text/html")
            if key == "mock-error-slow":
                time.sleep(10)
            elif key != api_key:
                return self._send(200, self._envelope(error="Invalid API key"))

            try:
                body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            except ValueError:
                body = {}
            if not isinstance(body, dict):
                body = {}

            if endpoint == "events":
                return self._send(200, self._envelope(filter_events(events, body)))
            return self._send(404, raw=NOT_FOUND_HTML, content_type="text/html")

    return Handler


def make_server(host="127.0.0.1", port=8081, api_key=DEFAULT_API_KEY, shift_to_now=False):
    server = ThreadingHTTPServer((host, port), make_handler(api_key, load_events(shift_to_now)))
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0", help="bind address (default 0.0.0.0, reachable from Docker)")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--api-key", default=os.environ.get("MOCK_API_KEY", DEFAULT_API_KEY))
    parser.add_argument("--shift-to-now", action="store_true", help="move fixture timestamps up to now")
    args = parser.parse_args()

    server = make_server(args.host, args.port, args.api_key, args.shift_to_now)
    print("Mock ShadowTrackr API on http://{}:{}{}  (API key: {})".format(args.host, args.port, API_PREFIX, args.api_key))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
