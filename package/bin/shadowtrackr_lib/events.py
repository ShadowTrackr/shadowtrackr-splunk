"""Incremental collection of the ShadowTrackr events feed.

We never use the API's update_only flag: it moves a cursor on the server, so
any other consumer of the same account would take events away from Splunk.

There are two ways to collect, chosen automatically:

id mode (API with since_id paging, the normal case)
  * every event has a unique, increasing id
  * each poll asks for id > checkpoint, page by page, until a short page
  * events inserted late (with an older timestamp) still get a new id, so
    nothing is missed and no overlap or hashing is needed
  * the checkpoint (next_since_id) is saved after each page has been written

window mode (older API without ids, and the backfill on first install)
  * stop  = now - lag, so events still being written are picked up next time
  * start = previous stop - overlap (or now - backfill on the first run)
  * the range is split into windows of at most max_window
  * duplicates in the overlap are dropped using a hash of the event content
  * the checkpoint is saved after each window has been written

Bootstrap (first install, or upgrading from a window checkpoint):
  1. remember the highest event id the API reports (latest_id), M0
  2. backfill with windows, remembering ids above M0 that were written
  3. continue in id mode from M0, skipping the ids written in step 2
Every event inserted after step 1 has an id above M0, so there is no gap.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

API_TS_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Without start/stop the API returns at most this many events. With both set
# there is no cap, but a window returning exactly this many is split in case
# one is ever introduced.
RESPONSE_CAP = 1000

# since_id page size (the API allows up to 5000).
PAGE_SIZE = 1000

# Safety limit on pages per run. The next run continues where this one stopped.
MAX_PAGES_PER_RUN = 500

ONE_SECOND = timedelta(seconds=1)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: Any) -> Optional[datetime]:
    """Parse an API timestamp such as 2026-10-31T03:29:33Z into aware UTC."""
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
    return dt.astimezone(timezone.utc)


def format_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(API_TS_FORMAT)


# Fields every API version returns. Hashing only these keeps an event's hash
# the same when the API adds fields, so upgrading does not create duplicates.
HASH_FIELDS = ("timestamp", "eventid", "level", "source", "msg", "cs1", "request", "dst", "fname")


def event_hash(event: Dict[str, Any]) -> str:
    """Stable id for an event, derived from its legacy content fields."""
    content = {k: event[k] for k in HASH_FIELDS if k in event}
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:20]


def event_id(event: Any) -> Optional[int]:
    """The API's unique event id, or None for older API versions."""
    if not isinstance(event, dict):
        return None
    value = event.get("id")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def plan_windows(start: datetime, stop: datetime, max_window: timedelta) -> Iterator[Tuple[datetime, datetime]]:
    """Split [start, stop] into consecutive inclusive windows.

    The API treats both bounds as inclusive at one-second resolution, so each
    window starts one second after the previous one ended.
    """
    window_start = start
    while window_start <= stop:
        window_stop = min(window_start + max_window - ONE_SECOND, stop)
        yield window_start, window_stop
        window_start = window_stop + ONE_SECOND


class Checkpoint:
    """Collection state, stored per input in the KV Store.

    last_stop          end of the last window (window mode), or the time of
                       the last run (id mode)
    seen               hashes of events inside the overlap (window mode)
    since_id           highest id written; set once in id mode
    skip_ids           ids above since_id that were already written
    bootstrap_since_id M0 while a bootstrap backfill is in progress
    """

    def __init__(
        self,
        last_stop: datetime,
        seen: Optional[Dict[str, int]] = None,
        since_id: Optional[int] = None,
        skip_ids: Optional[List[int]] = None,
        bootstrap_since_id: Optional[int] = None,
    ):
        self.last_stop = last_stop
        self.seen = seen or {}
        self.since_id = since_id
        self.skip_ids = sorted(skip_ids or [])
        self.bootstrap_since_id = bootstrap_since_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": 2,
            "last_stop": format_ts(self.last_stop),
            "seen": self.seen,
            "since_id": self.since_id,
            "skip_ids": self.skip_ids,
            "bootstrap_since_id": self.bootstrap_since_id,
        }

    @classmethod
    def from_dict(cls, data: Any) -> Optional["Checkpoint"]:
        if not isinstance(data, dict):
            return None
        last_stop = parse_ts(data.get("last_stop"))
        if last_stop is None:
            return None
        seen = data.get("seen")
        if not isinstance(seen, dict):
            seen = {}
        skip_ids = data.get("skip_ids")
        if not isinstance(skip_ids, list):
            skip_ids = []
        return cls(
            last_stop,
            {str(k): int(v) for k, v in seen.items() if isinstance(v, (int, float))},
            since_id=_int_or_none(data.get("since_id")),
            skip_ids=[i for i in (_int_or_none(x) for x in skip_ids) if i is not None],
            bootstrap_since_id=_int_or_none(data.get("bootstrap_since_id")),
        )


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


class EventCollector:
    def __init__(
        self,
        client: Any,
        load_checkpoint: Callable[[], Any],
        save_checkpoint: Callable[[Dict[str, Any]], None],
        write_event: Callable[[Dict[str, Any], Optional[float]], None],
        logger: logging.Logger,
        backfill: timedelta = timedelta(days=7),
        overlap: timedelta = timedelta(minutes=15),
        lag: timedelta = timedelta(seconds=60),
        max_window: timedelta = timedelta(hours=6),
        page_size: int = PAGE_SIZE,
        max_pages: int = MAX_PAGES_PER_RUN,
        now: Callable[[], datetime] = utcnow,
    ):
        self.client = client
        self.load_checkpoint = load_checkpoint
        self.save_checkpoint = save_checkpoint
        self.write_event = write_event
        self.logger = logger
        self.backfill = backfill
        self.overlap = overlap
        self.lag = lag
        self.max_window = max_window
        self.page_size = page_size
        self.max_pages = max_pages
        self.now = now

    def run(self) -> int:
        """Collect all new events and return how many were written."""
        now = self.now().astimezone(timezone.utc).replace(microsecond=0)
        stop = now - self.lag
        checkpoint = Checkpoint.from_dict(self.load_checkpoint())

        if checkpoint and checkpoint.since_id is not None:
            return self._run_id_mode(checkpoint, stop)

        # Window mode: first install, upgrade from a window checkpoint, an
        # interrupted bootstrap, or an API without ids.
        if checkpoint and checkpoint.bootstrap_since_id is not None:
            bootstrap_id = checkpoint.bootstrap_since_id
        else:
            bootstrap_id = self._latest_id()

        if checkpoint:
            start = checkpoint.last_stop - self.overlap
            seen = dict(checkpoint.seen)
            skip = set(checkpoint.skip_ids)
        else:
            start = now - self.backfill
            seen, skip = {}, set()
            self.logger.info("No checkpoint found, backfilling from %s", format_ts(start))

        total = 0
        last_stop = checkpoint.last_stop if checkpoint else start - ONE_SECOND
        for window_start, window_stop in plan_windows(start, stop, self.max_window):
            written, skipped, written_ids = self._collect_window(window_start, window_stop, seen)
            total += written
            if bootstrap_id is not None:
                skip.update(i for i in written_ids if i > bootstrap_id)
            # Only hashes that can reappear in the next overlap are kept.
            cutoff = int((window_stop - self.overlap).timestamp())
            seen = {h: ts for h, ts in seen.items() if ts >= cutoff}
            last_stop = window_stop
            self.save_checkpoint(
                Checkpoint(window_stop, seen, skip_ids=sorted(skip), bootstrap_since_id=bootstrap_id).to_dict()
            )
            self.logger.debug(
                "Window %s..%s: wrote %d events, skipped %d",
                format_ts(window_start),
                format_ts(window_stop),
                written,
                skipped,
            )

        if bootstrap_id is None:
            return total

        self.logger.info("Switching to since_id paging from id %d", bootstrap_id)
        switched = Checkpoint(last_stop, seen, since_id=bootstrap_id, skip_ids=sorted(skip))
        self.save_checkpoint(switched.to_dict())
        return total + self._run_id_mode(switched, stop)

    # --- id mode ----------------------------------------------------------

    def _latest_id(self) -> Optional[int]:
        """Highest event id right now (M0), or None if the API has no ids.

        latest_id from the API is used rather than the newest event's id: a
        late insert can have a higher id than the newest event by time.
        """
        latest = self.client.latest_id()
        if latest is not None:
            return latest
        self.logger.info("API has no event ids, using time windows")
        return None

    def _run_id_mode(self, checkpoint: Checkpoint, stop: datetime) -> int:
        since = checkpoint.since_id
        skip: Set[int] = set(checkpoint.skip_ids)
        # Hashes of recent events, so a fallback to window mode (if the API
        # ever drops since_id) does not duplicate the overlap.
        seen = dict(checkpoint.seen)
        cutoff = int((stop - self.overlap).timestamp())
        total = 0
        for _ in range(self.max_pages):
            data, next_since_id = self.client.events_since(since, self.page_size)
            if next_since_id is None:
                # The API no longer supports ids. Continue with time windows
                # from the last run on the next poll.
                self.logger.warning("API stopped returning next_since_id, falling back to time windows")
                self.save_checkpoint(Checkpoint(checkpoint.last_stop, seen).to_dict())
                return total

            records = []
            for event in data:
                eid = event_id(event)
                if eid is None:
                    self.logger.warning("Skipping event without an id")
                    continue
                if eid <= since or eid in skip:
                    continue
                records.append((eid, event))
            records.sort(key=lambda item: item[0])
            for eid, event in records:
                ts = parse_ts(event.get("timestamp"))
                if ts is None:
                    self.logger.warning("Event %d has no valid timestamp, using index time", eid)
                elif ts.timestamp() >= cutoff:
                    seen[event_hash(event)] = int(ts.timestamp())
                self.write_event(dict(event), ts.timestamp() if ts else None)
            total += len(records)

            highest = max([since, next_since_id] + [eid for eid, _ in records])
            skip = {i for i in skip if i > highest}
            seen = {h: t for h, t in seen.items() if t >= cutoff}
            self.save_checkpoint(Checkpoint(stop, seen, since_id=highest, skip_ids=sorted(skip)).to_dict())

            if len(data) < self.page_size:
                return total
            if highest == since:
                self.logger.warning("Full page without progress at since_id %d, stopping this run", since)
                return total
            since = highest

        self.logger.info("Reached %d pages in one run, continuing next run", self.max_pages)
        return total

    # --- window mode --------------------------------------------------------

    def _collect_window(self, start: datetime, stop: datetime, seen: Dict[str, int]) -> Tuple[int, int, List[int]]:
        prepared = []
        skipped = 0
        for event in self._fetch(start, stop):
            ts = parse_ts(event.get("timestamp")) if isinstance(event, dict) else None
            if ts is None:
                skipped += 1
                self.logger.warning("Skipping event without a valid timestamp")
                continue
            digest = event_hash(event)
            if digest in seen:
                skipped += 1
                continue
            seen[digest] = int(ts.timestamp())
            prepared.append((ts, digest, event))

        # The API groups results by event type, so sort by time before writing.
        prepared.sort(key=lambda item: (item[0], item[1]))
        written_ids = []
        for ts, digest, event in prepared:
            record = dict(event)
            if event_id(event) is None:
                # Older API versions have no id; the hash identifies the event.
                record["event_hash"] = digest
            else:
                written_ids.append(event_id(event))
            self.write_event(record, ts.timestamp())
        return len(prepared), skipped, written_ids

    def _fetch(self, start: datetime, stop: datetime) -> List[Dict[str, Any]]:
        events = self.client.events(format_ts(start), format_ts(stop))
        if len(events) == RESPONSE_CAP and stop > start:
            middle = start + (stop - start) / 2
            middle = middle.replace(microsecond=0)
            self.logger.info(
                "Window %s..%s returned exactly %d events, splitting it",
                format_ts(start),
                format_ts(stop),
                RESPONSE_CAP,
            )
            return self._fetch(start, middle) + self._fetch(middle + ONE_SECOND, stop)
        return events
