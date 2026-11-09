"""Inventory types: which endpoint, which KV Store collection, which key, which fields.

Each type turns the API's records into flat lookup rows. Only fields that are
useful for searching and enrichment are kept; large blobs (raw headers, full
whois, cipher suites) stay in ShadowTrackr.

Types whose shape we have not seen with real data (subnets, mailservers,
remote login services, blacklisted assets) use a generic projection: every
scalar field and every list of scalars, keyed on a hash of the record.
"""

import hashlib
import json
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

Row = Dict[str, Any]

# Tracking fields added to every row by the sync.
TRACKING_FIELDS = ("st_first_synced", "st_last_synced", "st_present", "organization_id", "organization")


def _scalars(values: Any) -> List[Any]:
    """A list of scalars (strings, numbers, bools) for a multivalue lookup field."""
    if values is None:
        return []
    if not isinstance(values, list):
        values = [values]
    return [v for v in values if isinstance(v, (str, int, float, bool)) and v != ""]


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes")
    return bool(value)


def _drop_empty(row: Row) -> Row:
    return {k: v for k, v in row.items() if v not in (None, "", [])}


def _seen(record: Row) -> Row:
    return {"first_seen": record.get("first_seen"), "last_seen": record.get("last_seen")}


def _health(record: Row) -> Row:
    return {
        "problem": _bool(record.get("problem")),
        "warning": _bool(record.get("warning")),
        "problems": _scalars(record.get("problems")),
        "warnings": _scalars(record.get("warnings")),
        "tags": _scalars(record.get("tags")),
    }


# --- projections ------------------------------------------------------------


def project_host(r: Row) -> Row:
    def ports(proto):
        return [p for p in (r.get(proto) or []) if isinstance(p, dict)]

    tcp, udp = ports("tcp"), ports("udp")
    hostnames = sorted({d.get("url") for d in (r.get("dns") or []) if isinstance(d, dict) and d.get("url")})
    return dict(
        ip=r.get("ip"),
        hostnames=hostnames,
        reverse_dns=_scalars(r.get("reverse_dns")),
        asn=r.get("asn"),
        asn_name=r.get("asn_name"),
        isp=r.get("isp"),
        prefix=r.get("prefix"),
        country=r.get("country"),
        city=r.get("city"),
        tcp_ports=[p.get("port") for p in tcp if p.get("port") is not None],
        udp_ports=[p.get("port") for p in udp if p.get("port") is not None],
        services=sorted({"{}/{} {}".format(p.get("port"), p.get("protocol") or proto, p.get("service") or "").strip()
                         for proto, items in (("tcp", tcp), ("udp", udp)) for p in items}),
        software=_scalars(r.get("software")),
        vulnerable=_bool(r.get("vulnerable")),
        website_count=len(r.get("websites") or []),
        **_health(r),
        **_seen(r),
    )


def project_website(r: Row) -> Row:
    return dict(
        url=r.get("url"),
        host=r.get("host"),
        http_status=r.get("http_status"),
        https_status=r.get("https_status"),
        title=_text(r.get("https_title")) or _text(r.get("http_title")),
        server=_text(r.get("https_server")) or _text(r.get("http_server")),
        software=_scalars(r.get("software")),
        cloud_provider=r.get("cloudprovider"),
        grade=r.get("grade"),
        vulnerable=_bool(r.get("vulnerable")),
        login_form=_bool(r.get("https_login_form")) or _bool(r.get("http_login_form")),
        login_insecure=_bool(r.get("http_login_insecure")) or _bool(r.get("https_login_insecure")),
        security_txt=_bool(r.get("security_txt_exists")),
        **_health(r),
        **_seen(r),
    )


def project_url(r: Row) -> Row:
    return dict(url=r.get("url"), pay_level_domain=_bool(r.get("pay_level_domain")),
                tags=_scalars(r.get("tags")), **_seen(r))


def project_domain(r: Row) -> Row:
    return dict(
        domain=r.get("domain"),
        registrar=r.get("registrar"),
        status=r.get("status"),
        nameservers=_scalars(r.get("nameservers")),
        mailservers=_scalars(r.get("mailservers")),
        spf=r.get("spf"),
        dnssec=r.get("dnssec"),
        creation_date=r.get("creation_date"),
        expiration_date=r.get("expiration_date"),
        updated_date=r.get("updated_date"),
        subdomain_count=len(r.get("subdomains") or []),
        tags=_scalars(r.get("tags")),
        **_seen(r),
    )


def project_certificate(r: Row) -> Row:
    protocols = [p for p in (r.get("protocols") or []) if isinstance(p, dict)]
    return dict(
        url=r.get("url"),
        host=r.get("host"),
        cn=r.get("cn"),
        sans=_scalars(r.get("subject_alternative_names")),
        issuer_o=r.get("issuer_o"),
        issuer_cn=r.get("issuer_cn"),
        grade=r.get("security_grade"),
        not_before=r.get("not_valid_before"),
        not_after=r.get("not_valid_after"),
        key_algorithm=r.get("key_algorithm"),
        signature_algorithm=r.get("signature_algorithm"),
        protocols=[p.get("name") for p in protocols if p.get("name")],
        weak_protocols=[p.get("name") for p in protocols if p.get("name") and p.get("state") not in ("ok", None)],
        serial=r.get("serialnumber"),
        sha256=r.get("sha256hash"),
        wildcard=_bool(r.get("wildcard")),
        revoked=_bool(r.get("revoked")),
        renewed=_bool(r.get("renewed")),
        cloud_provider=r.get("cloudprovider"),
        **_health(r),
        **_seen(r),
    )


DNS_FIELDS = ("url", "rrtype", "rrsubtype", "rrdata", "content", "priority", "mailserver",
              "v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf")


def project_dns(r: Row) -> Row:
    row = {k: r.get(k) for k in DNS_FIELDS}
    # Zero means "not applicable" for priority in the API's records.
    if row.get("priority") == 0:
        row["priority"] = None
    row.update(cloud_provider=r.get("cloudprovider"), tags=_scalars(r.get("tags")), **_seen(r))
    return row


def project_software(r: Row) -> Row:
    vulns = [v for v in (r.get("vulnerabilities") or []) if isinstance(v, dict)]
    scores = [v.get("cvss_score") for v in vulns if isinstance(v.get("cvss_score"), (int, float))]
    name = " ".join(_text(r.get(k)) for k in ("vendor", "product", "version", "patch") if r.get(k))
    return dict(
        software=name,
        vendor=r.get("vendor"),
        product=r.get("product"),
        version=r.get("version"),
        patch=r.get("patch"),
        asset_count=r.get("num_assets"),
        cve_count=len(vulns),
        max_cvss=max(scores) if scores else None,
        exploited=any(_bool(v.get("exploited")) for v in vulns),
        cisa_kev=any(_bool(v.get("cisa")) for v in vulns),
        **_seen(r),
    )


def project_cve(r: Row) -> Row:
    severity = r.get("severity")
    return dict(
        cve=r.get("cve"),
        asset=r.get("asset"),
        software=r.get("software"),
        cvss=r.get("cvss_score"),
        severity=severity.lower() if isinstance(severity, str) else None,
        st_score=r.get("shadowtrackr_cvss_score"),
        ncsc=r.get("ncsc_number"),
        ncsc_chance=r.get("ncsc_chance"),
        ncsc_impact=r.get("ncsc_impact"),
        exploited=_bool(r.get("exploited")),
        cisa_kev=_bool(r.get("cisa")),
        **_seen(r),
    )


def project_cloud_provider(r: Row) -> Row:
    return dict(cloud_provider=r.get("cloud_provider"), asset_count=r.get("assets"),
                urls=_scalars(r.get("urls")), **_seen(r))


def project_exposed_email(r: Row) -> Row:
    breaches = [b for b in (r.get("breaches") or []) if isinstance(b, dict)]
    dates = sorted(b.get("breached") for b in breaches if b.get("breached"))
    return dict(
        email=r.get("email"),
        websites=_scalars(r.get("websites")),
        breaches=[b.get("name") for b in breaches if b.get("name")],
        breach_count=len(breaches),
        latest_breach=dates[-1] if dates else None,
        **_seen(r),
    )


def project_suggestion(r: Row) -> Row:
    return dict(type=r.get("type"), content=r.get("content"), related_to=r.get("related_to"), found=r.get("found"))


def project_phishy_domain(r: Row) -> Row:
    whois = r.get("whois") if isinstance(r.get("whois"), dict) else {}
    web = r.get("web") if isinstance(r.get("web"), dict) else {}
    return dict(
        phishy_domain=r.get("phishy_url"),
        lookalike_of=r.get("original_url"),
        score=r.get("score"),
        registrar=r.get("registrar"),
        isp=r.get("isp"),
        country=r.get("country"),
        city=r.get("city"),
        nameservers=_scalars(r.get("nameservers")),
        mailservers=_scalars(r.get("mailservers")),
        has_mx=bool(_scalars(r.get("mailservers"))),
        has_certificate=bool(r.get("cert")),
        https_status=web.get("https_status") or None,
        https_title=web.get("https_title"),
        registered=whois.get("creation_date"),
        tags=_scalars(r.get("tags")),
        **_seen(r),
    )


# EU member states, as ShadowTrackr's country_is_eu() (lib/lib.php) has them for
# "headquartered outside the EU" in its Supplier Dependency Report.
EU_COUNTRIES = frozenset((
    "austria", "belgium", "bulgaria", "croatia", "cyprus", "czechia", "czech republic", "denmark", "estonia",
    "finland", "france", "germany", "greece", "hungary", "ireland", "italy", "latvia", "lithuania", "luxembourg",
    "malta", "netherlands", "the netherlands", "poland", "portugal", "romania", "slovakia", "slovenia", "spain",
    "sweden",
))

# What /query puts in name, country, city and control when the plan has no supplier mapping.
MASKED = "***"


def project_supplier(r: Row) -> Row:
    """A row of /query index=suppliers: one per supplier, with where it is controlled.

    Without supplier mapping in the plan, the API stars out name, country, city
    and control; those stay empty here and supplier_mapping is false.
    """
    masked = any(r.get(f) == MASKED for f in ("name", "country", "city", "control"))

    def clear(field: str) -> Optional[str]:
        value = _text(r.get(field)).strip()
        return None if value in ("", MASKED) else value

    types = [t.strip() for t in _text(r.get("type")).split(",") if t.strip()]
    country = clear("country")
    count = r.get("num_assets")
    return dict(
        supplier=clear("name"),
        supplier_type=types,
        country=country,
        city=clear("city"),
        control=clear("control"),
        in_eu=None if country is None else country.lower() in EU_COUNTRIES,
        asset_count=count if isinstance(count, int) and not isinstance(count, bool) else None,
        supplier_mapping=not masked,
        **_seen(r),
    )


def project_generic(r: Row) -> Row:
    """Every scalar and list of scalars, for types without a dedicated projection."""
    row = {}
    for key, value in r.items():
        if isinstance(value, (str, int, float, bool)) or value is None:
            row[key] = value
        elif isinstance(value, list) and all(isinstance(v, (str, int, float, bool)) for v in value):
            row[key] = value
    return row


def expand_internet_standards(records: Iterable[Row]) -> List[Row]:
    """One row per (url, category, check)."""
    rows = []
    for r in records:
        for category in r.get("checks") or []:
            if not isinstance(category, dict):
                continue
            for check in category.get("checks") or []:
                if not isinstance(check, dict):
                    continue
                rows.append(dict(
                    url=r.get("url"),
                    category=category.get("title"),
                    check=check.get("title"),
                    passed=_bool(check.get("passed")),
                    status=check.get("status"),
                    done=_bool(check.get("done")),
                    note=check.get("note"),
                ))
    return rows


def merge_cloud_providers(records: Iterable[Row]) -> List[Row]:
    """The API can list a provider more than once; keep one row per provider."""
    merged: Dict[str, Row] = {}
    for r in records:
        name = r.get("cloud_provider")
        if not name:
            continue
        row = merged.setdefault(name, {"cloud_provider": name, "assets": 0, "urls": [], "first_seen": None,
                                       "last_seen": None})
        row["assets"] += r.get("assets") if isinstance(r.get("assets"), int) else 0
        row["urls"] = sorted(set(row["urls"]) | set(_scalars(r.get("urls"))))
        for field, pick in (("first_seen", min), ("last_seen", max)):
            values = [v for v in (row[field], r.get(field)) if v]
            row[field] = pick(values) if values else None
    return list(merged.values())


def enrich_cves(records: List[Row], vulnerabilities: List[Row]) -> List[Row]:
    """Add exploited / cisa flags from /vulnerabilities to /cves_assets rows."""
    flags: Dict[str, Tuple[bool, bool]] = {}
    for group in vulnerabilities:
        for cve in group.get("cves") or []:
            if isinstance(cve, dict) and cve.get("cve"):
                old = flags.get(cve["cve"], (False, False))
                flags[cve["cve"]] = (old[0] or _bool(cve.get("exploited")), old[1] or _bool(cve.get("cisa")))
    out = []
    for r in records:
        exploited, cisa = flags.get(r.get("cve"), (False, False))
        out.append(dict(r, exploited=exploited, cisa=cisa))
    return out


# Per-CVE details that only the CVE lists nested in /hosts and /websites carry.
NESTED_CVE_FIELDS = ("shadowtrackr_cvss_score", "ncsc_number", "ncsc_chance", "ncsc_impact")


def add_nested_cve_details(records: List[Row], assets: List[Row]) -> List[Row]:
    """Add the ShadowTrackr score and the NCSC NL advisory per CVE to /cves_assets rows.

    These are only in the CVE lists nested in /hosts and /websites (per
    software: {"vulnerabilities": [{"cve" or "name": ..., "shadowtrackr_cvss_score": ...,
    "ncsc_number": ...}]}). They are the same for a CVE on every asset.
    """
    details: Dict[str, Row] = {}
    for asset in assets:
        for software in asset.get("vulnerabilities") or []:
            if not isinstance(software, dict):
                continue
            for cve in software.get("vulnerabilities") or []:
                if not isinstance(cve, dict):
                    continue
                cve_id = cve.get("cve") or cve.get("name")
                if not isinstance(cve_id, str):
                    continue
                found = details.setdefault(cve_id, {})
                score = cve.get("shadowtrackr_cvss_score")
                if isinstance(score, (int, float)) and not isinstance(score, bool):
                    found["shadowtrackr_cvss_score"] = max(score, found.get("shadowtrackr_cvss_score", score))
                for field in NESTED_CVE_FIELDS[1:]:
                    if isinstance(cve.get(field), str) and cve[field]:
                        found[field] = cve[field]
    return [dict(r, **details[r["cve"]]) if r.get("cve") in details else r for r in records]


# --- type registry ----------------------------------------------------------


class InventoryType:
    def __init__(
        self,
        name: str,
        endpoint: str,
        title: str,
        key_fields: Tuple[str, ...],
        project: Callable[[Row], Row],
        fields: Tuple[str, ...],
        expand: Optional[Callable[[List[Row]], List[Row]]] = None,
        extra: Tuple[Tuple[str, Callable[[List[Row], List[Row]], List[Row]]], ...] = (),
        query: Optional[str] = None,
    ):
        self.name = name
        self.endpoint = endpoint
        self.title = title
        self.key_fields = key_fields  # fields of the projected row that identify it
        self.project = project
        self.fields = fields  # projected fields, for the lookup definition
        self.expand = expand  # turns API records into rows to project (default: as is)
        self.extra = extra  # ((endpoint, combine), ...): other endpoints merged into the records, in order
        # Fetch with /query and this query instead of the list endpoint. endpoint then
        # only names the fixture and the mock data.
        self.query = query

    @property
    def collection(self) -> str:
        return "shadowtrackr_" + self.name

    def rows(self, records: List[Row], organization: Optional[Row] = None) -> List[Row]:
        """Projected, de-duplicated rows with a stable _key."""
        source = self.expand(records) if self.expand else records
        out: Dict[str, Row] = {}
        for record in source:
            if not isinstance(record, dict):
                continue
            row = _drop_empty(self.project(record))
            if organization:
                row["organization_id"] = organization["id"]
                row["organization"] = organization["name"]
            row["_key"] = self.key(row)
            out[row["_key"]] = row
        return list(out.values())

    def key(self, row: Row) -> str:
        if self.key_fields and all(row.get(k) not in (None, "") for k in self.key_fields):
            parts = [row.get(k) for k in self.key_fields]
        else:
            # No natural key: hash the content, without the fields that change.
            parts = {k: v for k, v in row.items() if k not in ("first_seen", "last_seen", "_key")}
        parts = [row.get("organization_id"), parts]
        digest = hashlib.sha1(json.dumps(parts, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return digest[:24]


def _f(*names: str) -> Tuple[str, ...]:
    return names


SEEN = _f("first_seen", "last_seen")
HEALTH = _f("problem", "warning", "problems", "warnings", "tags")

TYPES: Dict[str, InventoryType] = {t.name: t for t in [
    InventoryType("hosts", "hosts", "Hosts", ("ip",), project_host,
                  _f("ip", "hostnames", "reverse_dns", "asn", "asn_name", "isp", "prefix", "country", "city",
                     "tcp_ports", "udp_ports", "services", "software", "vulnerable", "website_count") + HEALTH + SEEN),
    InventoryType("websites", "websites", "Websites", ("url", "host"), project_website,
                  _f("url", "host", "http_status", "https_status", "title", "server", "software", "cloud_provider",
                     "grade", "vulnerable", "login_form", "login_insecure", "security_txt") + HEALTH + SEEN),
    InventoryType("urls", "urls", "URLs", ("url",), project_url, _f("url", "pay_level_domain", "tags") + SEEN),
    InventoryType("domains", "domains", "Domains", ("domain",), project_domain,
                  _f("domain", "registrar", "status", "nameservers", "mailservers", "spf", "dnssec", "creation_date",
                     "expiration_date", "updated_date", "subdomain_count", "tags") + SEEN),
    InventoryType("subnets", "subnets", "Subnets", (), project_generic, ()),
    InventoryType("certificates", "certificates", "Certificates", ("sha256", "host", "url"), project_certificate,
                  _f("url", "host", "cn", "sans", "issuer_o", "issuer_cn", "grade", "not_before", "not_after",
                     "key_algorithm", "signature_algorithm", "protocols", "weak_protocols", "serial", "sha256",
                     "wildcard", "revoked", "renewed", "cloud_provider") + HEALTH + SEEN),
    InventoryType("dns", "dns", "DNS records", ("url", "rrtype", "rrdata"), project_dns,
                  DNS_FIELDS + _f("cloud_provider", "tags") + SEEN),
    InventoryType("mailservers", "mailservers", "Mail servers", (), project_generic, ()),
    InventoryType("software", "software", "Software", ("vendor", "product", "version", "patch"), project_software,
                  _f("software", "vendor", "product", "version", "patch", "asset_count", "cve_count", "max_cvss",
                     "exploited", "cisa_kev") + SEEN),
    InventoryType("cves", "cves_assets", "Vulnerabilities (CVE per asset)", ("cve", "asset", "software"), project_cve,
                  _f("cve", "asset", "software", "cvss", "severity", "st_score", "ncsc", "ncsc_chance", "ncsc_impact",
                     "exploited", "cisa_kev") + SEEN,
                  extra=(("vulnerabilities", enrich_cves), ("hosts", add_nested_cve_details),
                         ("websites", add_nested_cve_details))),
    InventoryType("cloud_providers", "cloud_providers", "Cloud providers", ("cloud_provider",), project_cloud_provider,
                  _f("cloud_provider", "asset_count", "urls") + SEEN, expand=merge_cloud_providers),
    InventoryType("remote_login_services", "remote_login_services", "Remote login services", (), project_generic, ()),
    InventoryType("blacklisted_assets", "blacklisted_assets", "Blacklisted assets", (), project_generic, ()),
    InventoryType("exposed_emails", "exposed_email_addresses", "Exposed email addresses", ("email",),
                  project_exposed_email,
                  _f("email", "websites", "breaches", "breach_count", "latest_breach") + SEEN),
    InventoryType("suggestions", "suggestions", "Suggestions", ("type", "content"), project_suggestion,
                  _f("type", "content", "related_to", "found")),
    InventoryType("phishy_domains", "phishy_domains", "Phishy domains", ("phishy_domain",), project_phishy_domain,
                  _f("phishy_domain", "lookalike_of", "score", "registrar", "isp", "country", "city", "nameservers",
                     "mailservers", "has_mx", "has_certificate", "https_status", "https_title", "registered", "tags")
                  + SEEN),
    # /query, not /suppliers: the list endpoint has no country or control and misses
    # most suppliers (it reads a test copy of the suppliers index).
    InventoryType("suppliers", "suppliers", "Suppliers", ("supplier",), project_supplier,
                  _f("supplier", "supplier_type", "country", "city", "control", "in_eu", "asset_count",
                     "supplier_mapping") + SEEN,
                  query="index=suppliers"),
    InventoryType("internet_standards", "internet_standards", "Internet standards checks",
                  ("url", "category", "check"), lambda r: r,
                  _f("url", "category", "check", "passed", "status", "done", "note"),
                  expand=expand_internet_standards),
]}

DEFAULT_TYPES = tuple(TYPES)
