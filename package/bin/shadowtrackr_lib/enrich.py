"""Enrich IPs, hostnames and URLs with ShadowTrackr context from the inventory lookups.

Used by | stenrich. Values are normalized (URLs and host:port reduced to the
host, lower case, no trailing dot), each distinct value is looked up once per
search, and lookups are batched per collection, so a chunk with thousands of
events but a few hundred distinct values costs a handful of KV Store reads.

Only rows ShadowTrackr still reports (st_present=1) are used.
"""

import ipaddress
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

Row = Dict[str, Any]
# (collection, field, values) -> rows where field matches any of the values.
# For a multivalue field a row matches when any of its values matches.
Lookup = Callable[[str, str, Sequence[str]], List[Row]]

KINDS = ("auto", "ip", "domain")

# Every enriched result gets all of these (Splunk takes its columns from the
# first result), in this order, with this prefix.
FIELDS = (
    "known", "in_scope", "asset_type", "organization",
    "ip", "hostnames", "domain",
    "ports", "services", "software", "country", "asn_name", "cloud_provider",
    "problem", "warning", "problems", "warnings", "tags",
    "vulnerable", "cves", "cve_count", "max_cvss", "exploited", "cisa_kev",
    "web_grade", "cert_grade", "cert_expires", "cert_issuer",
    "phishy", "lookalike_of", "phishy_score",
    "first_seen", "last_seen",
)

# Certificate and website grades, best to worst. M = name mismatch, T = not trusted.
GRADES = ("A+", "A", "A-", "B", "C", "D", "E", "F", "M", "T")

_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62})(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}))*$")


def normalize(value: Any, kind: str = "auto") -> Optional[Tuple[str, str]]:
    """("ip" | "domain", normalized value), or None when the value is neither."""
    if isinstance(value, (list, tuple)):
        value = next((v for v in value if v not in (None, "")), None)
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None

    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return None
    elif "/" in text:
        text = text.split("/", 1)[0]
    if "@" in text:  # user@host from auth logs, or an email address
        text = text.rsplit("@", 1)[1]
    text = text.strip("[]")

    ip = _ip(text)
    if ip is None and text.count(":") == 1:  # host:port or a.b.c.d:port
        host, port = text.split(":")
        if port.isdigit():
            text = host
            ip = _ip(text)
    if ip is not None:
        return ("ip", ip) if kind in ("auto", "ip") else None
    if kind == "ip":
        return None

    text = text.rstrip(".")
    if "." not in text or not _HOSTNAME.match(text):
        return None
    return ("domain", text)


def _ip(text: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def parent_domains(name: str) -> List[str]:
    """a.b.example.com -> [a.b.example.com, b.example.com, example.com]."""
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


def _present(row: Row) -> bool:
    return row.get("st_present", 1) in (1, "1", True, 1.0)


def _list(value: Any) -> List[Any]:
    if value is None or value == "":
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _flag(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return bool(value)


def _num(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _uniq(values: Iterable[Any]) -> List[Any]:
    out, seen = [], set()
    for v in values:
        if v in (None, "") or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def worst_grade(grades: Iterable[Any]) -> Optional[str]:
    ranked = [g for g in grades if g in GRADES]
    return max(ranked, key=GRADES.index) if ranked else None


class Enricher:
    def __init__(self, lookup: Lookup, batch_size: int = 100):
        self.lookup = lookup
        self.batch_size = batch_size
        self.cache: Dict[Tuple[str, str], Row] = {}

    # --- public -------------------------------------------------------------

    def enrich(self, keys: Iterable[Tuple[str, str]]) -> Dict[Tuple[str, str], Row]:
        """Context for each normalized key; looks up only keys not seen before."""
        keys = set(keys)
        missing = [k for k in keys if k not in self.cache]
        ips = sorted({v for kind, v in missing if kind == "ip"})
        domains = sorted({v for kind, v in missing if kind == "domain"})
        if ips:
            self.cache.update(self._enrich_ips(ips))
        if domains:
            self.cache.update(self._enrich_domains(domains))
        return {k: self.cache[k] for k in keys}

    @staticmethod
    def unknown() -> Row:
        return {f: None for f in FIELDS}

    # --- lookups ------------------------------------------------------------

    def _rows(self, collection: str, field: str, values: Sequence[str]) -> List[Row]:
        rows: List[Row] = []
        values = list(values)
        for i in range(0, len(values), self.batch_size):
            rows.extend(r for r in self.lookup(collection, field, values[i:i + self.batch_size]) if _present(r))
        return rows

    def _by(self, collection: str, field: str, values: Sequence[str]) -> Dict[str, List[Row]]:
        """Rows grouped by each requested value they match (case-insensitive)."""
        wanted = set(values)
        grouped: Dict[str, List[Row]] = {v: [] for v in values}
        for row in self._rows(collection, field, values):
            for v in _list(row.get(field)):
                key = str(v).lower().rstrip(".")
                if key in wanted:
                    grouped[key].append(row)
        return grouped

    def _enrich_ips(self, ips: List[str]) -> Dict[Tuple[str, str], Row]:
        hosts = self._by("shadowtrackr_hosts", "ip", ips)
        websites = self._by("shadowtrackr_websites", "host", ips)
        cves = self._by("shadowtrackr_cves", "asset", ips)
        out = {}
        for ip in ips:
            h, w = hosts[ip], websites[ip]
            types = (["host"] if h else []) + (["website"] if w else [])
            ctx = self._common(h + w, cves[ip], certs=[], websites=w, types=types)
            ctx["ip"] = ip if ctx["known"] else None
            ctx["hostnames"] = _uniq([n for r in h for n in _list(r.get("hostnames"))]
                                     + [n[1] for n in (normalize(r.get("url")) for r in w) if n and n[0] == "domain"])
            out[("ip", ip)] = ctx
        return out

    def _enrich_domains(self, names: List[str]) -> Dict[Tuple[str, str], Row]:
        parents = sorted({p for n in names for p in parent_domains(n)})
        websites = self._by("shadowtrackr_websites", "url", names)
        certificates = self._by("shadowtrackr_certificates", "url", names)
        hosts = self._by("shadowtrackr_hosts", "hostnames", names)
        urls = self._by("shadowtrackr_urls", "url", names)
        dns = self._by("shadowtrackr_dns", "url", names)
        cves = self._by("shadowtrackr_cves", "asset", names)
        domains = self._by("shadowtrackr_domains", "domain", parents)
        phishy = self._by("shadowtrackr_phishy_domains", "phishy_domain", parents)
        out = {}
        for name in names:
            w, c, h, u, d = websites[name], certificates[name], hosts[name], urls[name], dns[name]
            types = [t for t, rows in (("website", w), ("certificate", c), ("hostname", h or d), ("url", u)) if rows]
            ctx = self._common(h + w + c + u + d, cves[name], certs=c, websites=w, types=types)
            owned = next((p for p in parent_domains(name) if domains[p]), None)
            ctx["domain"] = owned
            ctx["in_scope"] = 1 if (ctx["known"] or owned) else 0
            ctx["hostnames"] = [name]
            resolved = [r.get("rrdata") for r in d if r.get("rrtype") in ("A", "AAAA")]
            ctx["ip"] = _uniq([r.get("ip") for r in h] + [r.get("host") for r in w if _ip(str(r.get("host")))]
                              + [str(x).rstrip(".") for x in resolved if x])
            hit = next((phishy[p] for p in parent_domains(name) if phishy[p]), [])
            if hit:
                ctx["phishy"] = 1
                ctx["lookalike_of"] = _uniq(r.get("lookalike_of") for r in hit)
                scores = [s for s in (_num(r.get("score")) for r in hit) if s is not None]
                ctx["phishy_score"] = max(scores) if scores else None
            out[("domain", name)] = ctx
        return out

    def _common(self, rows: List[Row], cves: List[Row], certs: List[Row], websites: List[Row],
                types: List[str]) -> Row:
        cves = [c for c in cves if not _flag(c.get("resolved"))]  # resolved findings are not on the asset any more
        ctx = self.unknown()
        known = bool(rows)
        ctx["known"] = 1 if known else 0
        ctx["in_scope"] = 1 if known else 0
        ctx["phishy"] = 0
        if not known and not cves:
            return ctx
        ctx["asset_type"] = types or None
        ctx["organization"] = _uniq(r.get("organization") for r in rows) or None
        ctx["ports"] = _uniq([p for r in rows for p in _list(r.get("tcp_ports"))]) or None
        ctx["services"] = _uniq([s for r in rows for s in _list(r.get("services"))]) or None
        ctx["software"] = _uniq([s for r in rows for s in _list(r.get("software"))]) or None
        ctx["country"] = _uniq(r.get("country") for r in rows) or None
        ctx["asn_name"] = _uniq(r.get("asn_name") for r in rows) or None
        ctx["cloud_provider"] = _uniq(r.get("cloud_provider") for r in rows) or None
        ctx["problem"] = 1 if any(_flag(r.get("problem")) for r in rows) else 0
        ctx["warning"] = 1 if any(_flag(r.get("warning")) for r in rows) else 0
        ctx["problems"] = _uniq([p for r in rows for p in _list(r.get("problems"))]) or None
        ctx["warnings"] = _uniq([p for r in rows for p in _list(r.get("warnings"))]) or None
        ctx["tags"] = _uniq([t for r in rows for t in _list(r.get("tags"))]) or None
        ctx["vulnerable"] = 1 if (cves or any(_flag(r.get("vulnerable")) for r in rows)) else 0
        if cves:
            ctx["cves"] = _uniq(r.get("cve") for r in cves)
            ctx["cve_count"] = len(ctx["cves"])
            scores = [s for s in (_num(r.get("cvss")) for r in cves) if s is not None]
            ctx["max_cvss"] = max(scores) if scores else None
            ctx["exploited"] = 1 if any(_flag(r.get("exploited")) for r in cves) else 0
            ctx["cisa_kev"] = 1 if any(_flag(r.get("cisa_kev")) for r in cves) else 0
        ctx["web_grade"] = worst_grade(r.get("grade") for r in websites)
        if certs:
            ctx["cert_grade"] = worst_grade(r.get("grade") for r in certs)
            expiries = sorted(r.get("not_after") for r in certs if r.get("not_after"))
            ctx["cert_expires"] = expiries[0] if expiries else None
            ctx["cert_issuer"] = _uniq(r.get("issuer_o") or r.get("issuer_cn") for r in certs) or None
        seen_rows = rows + cves
        firsts = sorted(r.get("first_seen") for r in seen_rows if r.get("first_seen"))
        lasts = sorted(r.get("last_seen") for r in seen_rows if r.get("last_seen"))
        ctx["first_seen"] = firsts[0] if firsts else None
        ctx["last_seen"] = lasts[-1] if lasts else None
        return ctx


def apply(record: Row, ctx: Optional[Row], prefix: str = "st_") -> Row:
    """Add the context fields to a record. Single-value lists are unwrapped."""
    ctx = ctx or Enricher.unknown()
    for field in FIELDS:
        value = ctx.get(field)
        if isinstance(value, list):
            value = value[0] if len(value) == 1 else (value or None)
        record[prefix + field] = value
    return record
