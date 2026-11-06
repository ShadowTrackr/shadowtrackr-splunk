"""Live queries against the v4 /query endpoint, turned into Splunk results.

The endpoint takes the same query language as the ShadowTrackr GUI search
(index=hosts problem=yes, index=certificates by issuer, earliest=-7d, ...).
Rows come back as flat JSON objects whose shape depends on the index. This
module makes them Splunk friendly:

  * comma-separated list fields (tcp_ports, software, tags, ...) become
    multivalue fields
  * booleans become 1/0, like in the inventory lookups
  * nested objects and lists of objects become JSON strings
  * empty values are dropped
  * _time comes from last_seen, created, timestamp or found
  * every result has the same fields (Splunk takes the columns from the
    first result)
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

Row = Dict[str, Any]

DEFAULT_MAX_RESULTS = 10000

# Fields the API returns as one comma-separated string but which are lists.
LIST_FIELDS = frozenset((
    "tcp_ports", "udp_ports", "ports", "software", "tags", "cves", "protocols", "nameservers", "mailservers",
    "assets", "suites", "subject_alternative_names", "common_names", "hostnames", "reverse_dns", "urls",
    "http_scripts", "https_scripts", "http_css", "https_css", "scanned_urls", "websites",
))

# Where _time comes from, in order of preference.
TIME_FIELDS = ("last_seen", "created", "timestamp", "found", "first_seen")


def parse_time(value: Any) -> Optional[float]:
    """Epoch seconds for an API timestamp like 2026-11-06T04:37:02Z, or None."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _value(field: str, value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        if field in LIST_FIELDS and "," in value:
            parts = [p.strip() for p in value.split(",")]
            return [p for p in parts if p] or None
        return value if value != "" else None
    if isinstance(value, list):
        if all(isinstance(v, (str, int, float, bool)) for v in value):
            items = [_value(field, v) for v in value]
            return [v for v in items if v is not None] or None
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True) if value else None
    return str(value)


def to_result(row: Row) -> Row:
    """One API row as a Splunk result (without the common field set applied)."""
    result: Row = {}
    for field, raw in row.items():
        if not isinstance(field, str) or not field or field.startswith("_"):
            continue
        value = _value(field, raw)
        if value is not None:
            result[field] = value
    for field in TIME_FIELDS:
        ts = parse_time(row.get(field))
        if ts is not None:
            result["_time"] = ts
            break
    return result


def to_results(rows: List[Any]) -> List[Row]:
    """API rows as Splunk results, all with the same fields in a stable order."""
    results = [to_result(r) for r in rows if isinstance(r, dict)]
    fields: List[str] = []
    seen = set()
    for result in results:
        for field in result:
            if field not in seen:
                seen.add(field)
                fields.append(field)
    if "_time" in seen:
        fields.remove("_time")
        fields.insert(0, "_time")
    return [{f: r.get(f) for f in fields} for r in results]


def run_query(client: Any, query: str, max_results: int = DEFAULT_MAX_RESULTS) -> Tuple[List[Row], int]:
    """Run a query and return (results, total rows returned by the API).

    max_results of 0 or less means no limit. The API has no paging for
    /query, so the limit is applied after the response arrives.
    """
    query = (query or "").strip()
    if not query:
        raise ValueError("Give a query, e.g. query=\"index=hosts problem=yes\"")
    rows = client.post("query", {"q": query})
    total = len(rows)
    if max_results and max_results > 0:
        rows = rows[:max_results]
    return to_results(rows), total


def choose_account(names: List[str], requested: Optional[str]) -> Tuple[str, Optional[str]]:
    """Pick the account to query: (name, warning or None).

    Without account= the only account is used; with several, the first one
    alphabetically, with a warning that names the others.
    """
    if requested:
        if requested not in names:
            raise ValueError("No ShadowTrackr account named '{}'. Configured accounts: {}".format(
                requested, ", ".join(names) or "none"))
        return requested, None
    if not names:
        raise ValueError("No ShadowTrackr account configured. Add one under Configuration > Accounts.")
    if len(names) == 1:
        return names[0], None
    return names[0], "Using account '{}'. Pick another with account=<name> (configured: {}).".format(
        names[0], ", ".join(names))
