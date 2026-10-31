#!/usr/bin/env python3
"""Turn a raw ShadowTrackr API response into a redacted test fixture.

Usage:
  python3 -I tools/redact_events.py RAW.json OUT.json [--per-type 6] [--seed 1]

The raw file is the JSON envelope returned by POST /api/v4/events. Keep raw
responses outside the repository; only the redacted output belongs in
tests/fixtures/.

Redaction is deterministic within one run:
  * IPv4 addresses   -> RFC 5737 documentation ranges
  * IPv6 addresses   -> 2001:db8::/32 (RFC 3849)
  * hostnames        -> the most common registered domain becomes example.com,
                        others example-N.net; non-generic labels become hN
  * e-mail addresses -> userN@example.org
  * serials, ids and long hex strings -> fake values

The output still has to be reviewed by a human before it is committed.
"""

import argparse
import collections
import ipaddress
import json
import random
import re
import sys

TLDS = ("com", "net", "org", "io", "me", "cloud", "de", "uk", "nl", "eu", "app", "at", "host",
        "dev", "co", "be", "ch", "fr", "info", "biz", "default", "local", "internal")
GENERIC_LABELS = {"www", "mail", "api", "admin", "docs", "app", "dev", "test", "staging", "monitoring",
                  "grafana", "vpn", "remote", "portal", "shop", "blog", "events", "status", "ftp",
                  "smtp", "mx", "ns1", "ns2", "old", "auth", "login", "cdn", "static", "git"}
DOC_V4_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

HOST_RE = re.compile(
    r"(?<![\w-])(?<![\w-]\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:%s)(?![\w-])" % "|".join(TLDS),
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])", re.IGNORECASE)
HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
PARAM_ID_RE = re.compile(r"\b(wid|cid|serial)=([^&\s\"]+)")


def registered_domain(host):
    labels = host.lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "org", "ac", "gov", "net"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class Redactor:
    def __init__(self, primary_domain, rng):
        self.rng = rng
        self.primary = primary_domain
        self.domains = {primary_domain: "example.com"}
        self.labels = {}
        self.ipv4 = {}
        self.ipv6 = {}
        self.emails = {}
        self.hexes = {}
        self.ids = {}

    def domain(self, reg):
        if reg not in self.domains:
            self.domains[reg] = "example-{}.net".format(len(self.domains))
        return self.domains[reg]

    def host(self, match):
        host = match.group(0)
        reg = registered_domain(host)
        if reg == "example.org" or reg in self.domains.values():
            # Already a placeholder (e.g. from the e-mail pass).
            return host
        prefix = host[: len(host) - len(reg)].rstrip(".")
        parts = []
        for label in prefix.split(".") if prefix else []:
            low = label.lower()
            if low in GENERIC_LABELS:
                parts.append(low)
            else:
                parts.append(self.labels.setdefault(low, "h{}".format(len(self.labels) + 1)))
        return ".".join(parts + [self.domain(reg)])

    def ip4(self, match):
        ip = match.group(0)
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return ip
        if ip not in self.ipv4:
            n = len(self.ipv4)
            self.ipv4[ip] = "{}{}".format(DOC_V4_NETS[n // 250 % 3], n % 250 + 1)
        return self.ipv4[ip]

    def ip6(self, match):
        ip = match.group(0)
        try:
            ipaddress.IPv6Address(ip)
        except ValueError:
            return ip
        if ip not in self.ipv6:
            self.ipv6[ip] = "2001:db8::{:x}".format(len(self.ipv6) + 1)
        return self.ipv6[ip]

    def email(self, match):
        addr = match.group(0).lower()
        if addr not in self.emails:
            self.emails[addr] = "user{}@example.org".format(len(self.emails) + 1)
        return self.emails[addr]

    def hexstr(self, match):
        value = match.group(0)
        if value not in self.hexes:
            self.hexes[value] = "".join(self.rng.choice("0123456789abcdef") for _ in value)
            if value.isupper():
                self.hexes[value] = self.hexes[value].upper()
        return self.hexes[value]

    def param_id(self, match):
        key, value = match.group(1), match.group(2)
        if (key, value) not in self.ids:
            if key == "serial":
                fake = "".join(self.rng.choice("0123456789ABCDEF") for _ in value)
            else:
                fake = str(10000000 + len(self.ids))
            self.ids[(key, value)] = fake
        return "{}={}".format(key, self.ids[(key, value)])

    def text(self, value):
        value = EMAIL_RE.sub(self.email, value)
        value = PARAM_ID_RE.sub(self.param_id, value)
        value = HEX_RE.sub(self.hexstr, value)
        value = IPV6_RE.sub(self.ip6, value)
        value = IPV4_RE.sub(self.ip4, value)
        value = HOST_RE.sub(self.host, value)
        return value

    def event(self, event):
        return {k: self.text(v) if isinstance(v, str) and k not in ("timestamp", "source") else v
                for k, v in event.items()}


def select(events, per_type, rng):
    """Keep up to per_type events of every (source, eventid), spread over time."""
    groups = collections.defaultdict(list)
    for e in events:
        groups[(e.get("source"), e.get("eventid"))].append(e)
    chosen = []
    for key in sorted(groups, key=str):
        items = sorted(groups[key], key=lambda e: e["timestamp"])
        if len(items) <= per_type:
            chosen.extend(items)
        else:
            step = len(items) / per_type
            chosen.extend(items[int(i * step)] for i in range(per_type))
    return sorted(chosen, key=lambda e: e["timestamp"])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("raw")
    parser.add_argument("out")
    parser.add_argument("--per-type", type=int, default=6)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    with open(args.raw, encoding="utf-8") as f:
        data = json.load(f)["data"]
    rng = random.Random(args.seed)
    selected = select(data, args.per_type, rng)

    hosts = collections.Counter()
    for e in data:
        for m in HOST_RE.finditer(json.dumps(e)):
            hosts[registered_domain(m.group(0))] += 1
    primary = hosts.most_common(1)[0][0] if hosts else "example.com"

    redactor = Redactor(primary, rng)
    redacted = [redactor.event(e) for e in selected]
    envelope = {"results": "{} results found".format(len(redacted)), "error": "", "data": redacted}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("wrote {} events ({} domains, {} IPv4, {} IPv6 mapped)".format(
        len(redacted), len(redactor.domains), len(redactor.ipv4), len(redactor.ipv6)), file=sys.stderr)


if __name__ == "__main__":
    main()
