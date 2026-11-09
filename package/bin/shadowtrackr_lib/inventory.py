"""Inventory snapshots: sync ShadowTrackr list endpoints into KV Store lookups.

Every run fetches the current inventory per type (the API returns what was
seen recently, there is no paging) and reconciles it with the lookup:

  * rows are upserted by a stable _key (see inventory_types)
  * st_first_synced / st_last_synced record when the app first and last saw a row
  * rows that are no longer returned get st_present=0 and are deleted once
    they have been gone for the retention period
  * if a type that had rows suddenly returns nothing, nothing is marked gone
    until that happens on two runs in a row (protects against API glitches)

One summary per type and organization is returned for the summary index.
A failing type is logged and reported; the other types still sync.
"""

import json
import logging
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional

from .client import AuthError, ShadowTrackrError, TransientError
from .inventory_types import TYPES, InventoryType, Row

EMPTY_RUNS_BEFORE_GONE = 2

# The inventory is a full snapshot per run; more often than hourly only loads the API.
MIN_INTERVAL = 3600
MAX_INTERVAL = 7 * 86400
_CRON = re.compile(r"^(?:[0-9*,/-]+\s+){4}[0-9*,/-]+$")


def validate_interval(value: Any) -> None:
    """Accept seconds between MIN_INTERVAL and MAX_INTERVAL, or a 5-field cron schedule.

    UCC replaces the validators of a field named "interval" with a generic
    pattern, so the limits are checked here, when Splunk validates the input.
    """
    text = str(value if value is not None else "").strip()
    if _CRON.match(text):
        return
    try:
        seconds = float(text)
    except ValueError:
        raise ValueError("interval must be seconds or a cron schedule such as 0 7,10,13,16 * * 1-5") from None
    if not MIN_INTERVAL <= seconds <= MAX_INTERVAL:
        raise ValueError("interval must be between {} and {} seconds, or a cron schedule".format(
            MIN_INTERVAL, MAX_INTERVAL))


class KVStore:
    """What the collector needs from the KV Store (the Splunk adapter and test fakes implement it)."""

    def load(self, collection: str) -> List[Row]:
        raise NotImplementedError

    def save(self, collection: str, rows: List[Row]) -> None:
        raise NotImplementedError

    def delete(self, collection: str, keys: List[str]) -> None:
        raise NotImplementedError


def list_organizations(client: Any) -> Optional[List[Dict[str, Any]]]:
    """Organizations for a group key, or None for a normal key.

    Any group key may list its organizations, including a Group read-only key,
    as long as no groupcode is sent (that would also return the keys and need
    group_admin). A normal key is refused: live answers "No groupcode provided"
    with HTTP 200, and a 401/403 counts as refused too.

    Transient failures are raised: taking a group key for a normal one would
    sync nothing, because group keys get no data without organization_id.
    """
    try:
        envelope = client.request("organizations", {})
    except TransientError:
        raise
    except ShadowTrackrError:
        return None
    data = envelope.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("organizations"), list):
        return None
    orgs = []
    for org in data["organizations"]:
        if isinstance(org, dict) and isinstance(org.get("oid"), int):
            orgs.append({"id": org["oid"], "name": str(org.get("name") or org["oid"])})
    return orgs


def reconcile(
    inv_type: InventoryType,
    rows: List[Row],
    existing: List[Row],
    now: int,
    retention_seconds: int,
    empty_runs: int,
    organization_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Work out what to save and delete. Pure: no I/O.

    existing is every row in the collection; only rows of this organization
    are considered (all rows for a normal key).
    """
    mine = {r["_key"]: r for r in existing if r.get("organization_id") == organization_id and r.get("_key")}
    previously_present = sum(1 for r in mine.values() if r.get("st_present", 1) in (1, "1", True))

    save: List[Row] = []
    seen_keys = set()
    new = 0
    for row in rows:
        old = mine.get(row["_key"])
        if old is None:
            new += 1
        first = old.get("st_first_synced") if old else None
        save.append(dict(row, st_first_synced=first or now, st_last_synced=now, st_present=1))
        seen_keys.add(row["_key"])

    skip_gone = not rows and previously_present > 0 and empty_runs + 1 < EMPTY_RUNS_BEFORE_GONE
    gone = 0
    delete: List[str] = []
    for key, old in mine.items():
        if key in seen_keys:
            continue
        present = old.get("st_present", 1) in (1, "1", True)
        if present and not skip_gone:
            gone += 1
            save.append(dict(old, st_present=0))
        elif not present and now - _int(old.get("st_last_synced"), now) > retention_seconds:
            delete.append(key)

    return {
        "save": save,
        "delete": delete,
        "empty_runs": (empty_runs + 1) if not rows else 0,
        "summary": {
            "type": inv_type.name,
            "status": "skipped_empty" if skip_gone else "ok",
            "present": len(rows),
            "new": new,
            "gone": gone,
            "deleted": len(delete),
        },
    }


def _int(value: Any, default: int) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


class InventoryCollector:
    def __init__(
        self,
        client: Any,
        kv: KVStore,
        load_state: Callable[[], Any],
        save_state: Callable[[Dict[str, Any]], None],
        logger: logging.Logger,
        types: Iterable[str],
        retention_days: int = 30,
        now: Callable[[], float] = time.time,
    ):
        self.client = client
        self.kv = kv
        self.load_state = load_state
        self.save_state = save_state
        self.logger = logger
        self.types = [TYPES[t] for t in types if t in TYPES]
        self.retention_seconds = retention_days * 86400
        self.now = now
        self._responses: Dict[Any, List[Row]] = {}

    def run(self) -> List[Dict[str, Any]]:
        """Sync every selected type and return one summary per type and organization."""
        state = self.load_state() or {}
        if not isinstance(state, dict):
            state = {}
        empty_runs = state.get("empty_runs") if isinstance(state.get("empty_runs"), dict) else {}

        organizations = list_organizations(self.client)
        if organizations is not None:
            self.logger.info("Group key with %d organizations", len(organizations))
        targets = organizations if organizations is not None else [None]

        self._responses = {}
        summaries = []
        for inv_type in self.types:
            try:
                existing = self.kv.load(inv_type.collection)
            except Exception as e:  # KV Store unavailable: nothing can be synced for this type
                self.logger.error("Cannot read KV Store collection %s: %s", inv_type.collection, e)
                summaries.append({"type": inv_type.name, "status": "error", "error": "KV Store: {}".format(e)})
                continue
            for org in targets:
                summary = self._sync(inv_type, org, existing, empty_runs)
                summaries.append(summary)
            self.save_state({"empty_runs": empty_runs})
        synced = [s for s in summaries if s.get("status") in ("ok", "skipped_empty")]
        if organizations is None and synced and not any(s["present"] for s in synced):
            self.logger.warning(
                "Every inventory type returned no rows. If this is a group (MSSP) key, it could not list its "
                "organizations, and a group key gets no data without one. Check the key in ShadowTrackr.")
        return summaries

    def _sync(self, inv_type: InventoryType, org: Optional[Dict[str, Any]], existing: List[Row],
              empty_runs: Dict[str, int]) -> Dict[str, Any]:
        org_id = org["id"] if org else None
        state_key = "{}:{}".format(inv_type.name, org_id or "")
        body = {"organization_id": org_id} if org else {}
        try:
            records = self._fetch(inv_type.endpoint, body)
            for endpoint, combine in inv_type.extra:
                records = combine(records, self._fetch(endpoint, body))
            rows = inv_type.rows(records, org)
        except AuthError:
            raise  # a bad key affects every type; let the input report it once
        except ShadowTrackrError as e:
            self.logger.error("Fetching %s failed: %s", inv_type.name, e)
            return self._with_org({"type": inv_type.name, "status": "error", "error": str(e)}, org)

        result = reconcile(inv_type, rows, existing, int(self.now()), self.retention_seconds,
                           empty_runs.get(state_key, 0), org_id)
        if result["save"]:
            self.kv.save(inv_type.collection, result["save"])
        if result["delete"]:
            self.kv.delete(inv_type.collection, result["delete"])
        empty_runs[state_key] = result["empty_runs"]
        summary = result["summary"]
        if summary["status"] == "skipped_empty":
            self.logger.warning("%s returned no rows; keeping existing rows until this happens twice", inv_type.name)
        self.logger.info("Synced %s: %d present, %d new, %d gone, %d deleted", inv_type.name, summary["present"],
                         summary["new"], summary["gone"], summary["deleted"])
        return self._with_org(summary, org)

    def _fetch(self, endpoint: str, body: Dict[str, Any]) -> List[Row]:
        """POST once per endpoint and organization per run (CVEs reuse the hosts and websites answers)."""
        key = (endpoint, json.dumps(body, sort_keys=True))
        if key not in self._responses:
            self._responses[key] = self.client.post(endpoint, body)
        return self._responses[key]

    @staticmethod
    def _with_org(summary: Dict[str, Any], org: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if org:
            summary = dict(summary, organization_id=org["id"], organization=org["name"])
        return summary
