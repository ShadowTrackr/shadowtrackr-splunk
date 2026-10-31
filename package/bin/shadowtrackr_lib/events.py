"""Incremental collection of the ShadowTrackr events feed.

We do not use the API's update_only flag: it moves a cursor on the server, so
any other consumer of the same account would take events away from Splunk.
Instead every poll requests an explicit [start, stop] window and keeps its own
checkpoint.

How a poll works:
  * stop  = now - lag, so events still being written are picked up next time
  * start = previous stop - overlap (or now - backfill on the first run)
  * the range is split into windows of at most max_window
  * events have no unique id, so each one gets a hash of its content; hashes
    seen inside the overlap are kept in the checkpoint to drop duplicates
  * the checkpoint is saved after each window has been written
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

API_TS_FORMAT = "%Y-%m-%dT%H:%M:%S"

# Without start/stop the API returns at most this many events. With both set
# no cap has been observed, but a window returning exactly this many is split
# in case one is ever introduced.
RESPONSE_CAP = 1000

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


def event_hash(event: Dict[str, Any]) -> str:
    """Stable id for an event, derived from its full content."""
    canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:20]


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
    """Where the last poll stopped, plus hashes of events inside the overlap."""

    def __init__(self, last_stop: datetime, seen: Optional[Dict[str, int]] = None):
        self.last_stop = last_stop
        self.seen = seen or {}

    def to_dict(self) -> Dict[str, Any]:
        return {"version": 1, "last_stop": format_ts(self.last_stop), "seen": self.seen}

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
        return cls(last_stop, {str(k): int(v) for k, v in seen.items() if isinstance(v, (int, float))})


class EventCollector:
    def __init__(
        self,
        client: Any,
        load_checkpoint: Callable[[], Any],
        save_checkpoint: Callable[[Dict[str, Any]], None],
        write_event: Callable[[Dict[str, Any], float], None],
        logger: logging.Logger,
        backfill: timedelta = timedelta(days=7),
        overlap: timedelta = timedelta(minutes=15),
        lag: timedelta = timedelta(seconds=60),
        max_window: timedelta = timedelta(hours=6),
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
        self.now = now

    def run(self) -> int:
        """Collect all new events and return how many were written."""
        now = self.now().astimezone(timezone.utc).replace(microsecond=0)
        stop = now - self.lag

        checkpoint = Checkpoint.from_dict(self.load_checkpoint())
        if checkpoint:
            start = checkpoint.last_stop - self.overlap
            seen = dict(checkpoint.seen)
        else:
            start = now - self.backfill
            seen = {}
            self.logger.info("No checkpoint found, backfilling from %s", format_ts(start))

        if start > stop:
            return 0

        total = 0
        for window_start, window_stop in plan_windows(start, stop, self.max_window):
            written, skipped = self._collect_window(window_start, window_stop, seen)
            total += written
            # Only hashes that can reappear in the next overlap are kept.
            cutoff = int((window_stop - self.overlap).timestamp())
            seen = {h: ts for h, ts in seen.items() if ts >= cutoff}
            self.save_checkpoint(Checkpoint(window_stop, seen).to_dict())
            self.logger.debug(
                "Window %s..%s: wrote %d events, skipped %d",
                format_ts(window_start),
                format_ts(window_stop),
                written,
                skipped,
            )
        return total

    def _collect_window(self, start: datetime, stop: datetime, seen: Dict[str, int]) -> Tuple[int, int]:
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
        for ts, digest, event in prepared:
            record = dict(event)
            record["event_hash"] = digest
            self.write_event(record, ts.timestamp())
        return len(prepared), skipped

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
