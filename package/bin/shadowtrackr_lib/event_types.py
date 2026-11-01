"""Turn the API's /event_types catalogue into KV Store lookup records.

The catalogue is the source of signatures and categories at search time. A
small CSV (lookups/shadowtrackr_event_type_overrides.csv) corrects the CIM
classification where the catalogue's is_change heuristic is off.
"""

from typing import Any, Dict, List

REFRESH_INTERVAL_SECONDS = 24 * 3600


def _bool_text(value: Any) -> str:
    if isinstance(value, str):
        return "true" if value.strip().lower() in ("1", "true", "yes") else "false"
    return "true" if value else "false"


def humanize(name: str) -> str:
    """Fallback signature from a snake_case name: 'cert_renewed' -> 'Cert renewed'."""
    text = " ".join(part for part in str(name).replace("-", "_").split("_") if part)
    return text[:1].upper() + text[1:]


def to_records(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        eventid = row.get("eventid")
        if isinstance(eventid, bool) or not isinstance(eventid, int) or eventid in seen:
            continue
        seen.add(eventid)
        name = str(row.get("name") or "")
        title = row.get("title") or humanize(name)
        default_level = row.get("default_level")
        aliases = row.get("aliases")
        records.append(
            {
                "_key": str(eventid),
                "eventid": eventid,
                "name": name,
                "title": str(title),
                "category": str(row.get("category") or "other"),
                "source": str(row.get("source") or ""),
                "is_change": _bool_text(row.get("is_change")),
                "default_level": default_level if isinstance(default_level, int) else "",
                "aliases": ",".join(str(a) for a in aliases) if isinstance(aliases, list) else "",
                "action": str(row.get("action") or ""),
            }
        )
    return records
