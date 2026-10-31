from datetime import datetime, timedelta, timezone

import pytest

from mock_api.server import DEFAULT_API_KEY, filter_events
from shadowtrackr_lib.client import ShadowTrackrClient, TransientError
from shadowtrackr_lib.events import (
    RESPONSE_CAP,
    Checkpoint,
    EventCollector,
    event_hash,
    format_ts,
    parse_ts,
    plan_windows,
)

UTC = timezone.utc


def dt(text):
    return parse_ts(text)


# --- timestamps and hashing ----------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["2026-10-31T03:29:33Z", "2026-10-31T03:29:33", "2026-10-31 03:29:33", "2026-10-31T03:29:33+00:00"],
)
def test_parse_ts_accepts_api_formats(text):
    assert parse_ts(text) == datetime(2026, 10, 31, 3, 29, 33, tzinfo=UTC)


def test_parse_ts_converts_offsets_to_utc():
    assert parse_ts("2026-10-31T05:29:33+02:00") == datetime(2026, 10, 31, 3, 29, 33, tzinfo=UTC)


@pytest.mark.parametrize("value", [None, "", "garbage", 12345])
def test_parse_ts_rejects_invalid(value):
    assert parse_ts(value) is None


def test_format_ts_is_api_format():
    assert format_ts(datetime(2026, 3, 13, 10, 0, 0, tzinfo=UTC)) == "2026-03-13T10:00:00"


def test_event_hash_ignores_key_order_and_detects_changes():
    a = {"timestamp": "t", "eventid": 1, "msg": "m"}
    b = {"msg": "m", "eventid": 1, "timestamp": "t"}
    assert event_hash(a) == event_hash(b)
    assert event_hash(a) != event_hash(dict(a, msg="other"))


def test_fixture_events_have_unique_hashes(fixture_events):
    hashes = [event_hash(e) for e in fixture_events]
    assert len(set(hashes)) == len(hashes)


# --- windows --------------------------------------------------------------


def test_plan_windows_covers_range_without_gaps_or_overlap():
    start, stop = dt("2026-10-01T00:00:00Z"), dt("2026-10-02T03:00:00Z")
    windows = list(plan_windows(start, stop, timedelta(hours=6)))
    assert windows[0][0] == start
    assert windows[-1][1] == stop
    for (_, prev_stop), (next_start, _) in zip(windows, windows[1:]):
        assert next_start == prev_stop + timedelta(seconds=1)
    assert all(s - e < timedelta(hours=6) for e, s in windows)
    assert len(windows) == 5


def test_plan_windows_single_second():
    t = dt("2026-10-01T00:00:00Z")
    assert list(plan_windows(t, t, timedelta(hours=6))) == [(t, t)]


def test_plan_windows_empty_when_start_after_stop():
    assert list(plan_windows(dt("2026-10-02T00:00:00Z"), dt("2026-10-01T00:00:00Z"), timedelta(hours=1))) == []


# --- checkpoint -----------------------------------------------------------


def test_checkpoint_round_trip():
    cp = Checkpoint(dt("2026-10-30T10:00:00Z"), {"abc": 1793354400})
    restored = Checkpoint.from_dict(cp.to_dict())
    assert restored.last_stop == cp.last_stop
    assert restored.seen == cp.seen


@pytest.mark.parametrize("data", [None, "x", {}, {"last_stop": "garbage"}, [1, 2]])
def test_checkpoint_invalid_data_is_ignored(data):
    assert Checkpoint.from_dict(data) is None


def test_checkpoint_with_bad_seen_still_loads():
    cp = Checkpoint.from_dict({"last_stop": "2026-10-30T10:00:00", "seen": "nope"})
    assert cp.last_stop == dt("2026-10-30T10:00:00Z")
    assert cp.seen == {}


# --- collector ------------------------------------------------------------


class FakeClient:
    """Serves events like the real API, using the mock server's filter."""

    def __init__(self, events, fail_on_call=None):
        self.events_data = list(events)
        self.calls = []
        self.fail_on_call = fail_on_call

    def events(self, start, stop):
        self.calls.append((start, stop))
        if self.fail_on_call is not None and len(self.calls) == self.fail_on_call:
            raise TransientError("boom")
        return filter_events(self.events_data, {"start": start, "stop": stop})


class Harness:
    def __init__(self, client, now, logger, **kwargs):
        self.state = None
        self.saved = []
        self.written = []
        self.now = now
        self.collector = EventCollector(
            client=client,
            load_checkpoint=lambda: self.state,
            save_checkpoint=self._save,
            write_event=lambda record, ts: self.written.append((record, ts)),
            logger=logger,
            now=lambda: self.now,
            **kwargs
        )

    def _save(self, state):
        self.state = state
        self.saved.append(state)

    def run(self):
        return self.collector.run()


def newest(events):
    return max(dt(e["timestamp"]) for e in events)


def oldest(events):
    return min(dt(e["timestamp"]) for e in events)


def test_first_run_backfills_and_writes_sorted_events(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=now - oldest(fixture_events))

    count = h.run()

    assert count == len(fixture_events) == len(h.written)
    times = [ts for _, ts in h.written]
    assert times == sorted(times)
    assert all(rec["event_hash"] == event_hash({k: v for k, v in rec.items() if k != "event_hash"})
               for rec, _ in h.written)
    assert h.state["last_stop"] == format_ts(now - timedelta(seconds=60))


def test_backfill_limits_how_far_back_we_go(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=2))
    h.run()
    expected = [e for e in fixture_events if dt(e["timestamp"]) >= now - timedelta(days=2)]
    assert len(h.written) == len(expected)


def test_written_timestamp_matches_event(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60))
    h.run()
    for record, ts in h.written:
        assert ts == dt(record["timestamp"]).timestamp()


def test_second_run_without_new_events_writes_nothing(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60))
    h.run()
    h.now = now + timedelta(minutes=5)
    assert h.run() == 0


def test_overlap_catches_late_event_without_duplicates(fixture_events, logger):
    events = list(fixture_events)
    client = FakeClient(events)
    now = newest(events) + timedelta(minutes=5)
    h = Harness(client, now, logger, backfill=timedelta(days=60), overlap=timedelta(minutes=15))
    h.run()
    last_stop = dt(h.state["last_stop"])

    # An event that shows up late, timestamped before the last checkpoint
    # but inside the overlap.
    late = {"timestamp": format_ts(last_stop - timedelta(minutes=10)) + "Z", "eventid": 1, "level": 50,
            "source": "hosts", "msg": "late event"}
    client.events_data.append(late)
    h.now = now + timedelta(minutes=5)

    assert h.run() == 1
    assert h.written[-1][0]["msg"] == "late event"


def test_event_later_than_overlap_is_not_collected(fixture_events, logger):
    """Documents the limit of the overlap: much older late events are missed."""
    client = FakeClient(fixture_events)
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(client, now, logger, backfill=timedelta(days=60), overlap=timedelta(minutes=15))
    h.run()
    last_stop = dt(h.state["last_stop"])
    client.events_data.append({"timestamp": format_ts(last_stop - timedelta(hours=2)) + "Z", "eventid": 1,
                               "level": 50, "source": "hosts", "msg": "too late"})
    h.now = now + timedelta(minutes=5)
    assert h.run() == 0


def test_new_events_after_checkpoint_are_collected(fixture_events, logger):
    client = FakeClient(fixture_events)
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(client, now, logger, backfill=timedelta(days=60))
    h.run()
    new = {"timestamp": format_ts(now + timedelta(minutes=1)) + "Z", "eventid": 2, "level": 91,
           "source": "hosts", "msg": "new event"}
    client.events_data.append(new)
    h.now = now + timedelta(minutes=5)
    assert h.run() == 1


def test_seen_hashes_are_pruned_to_overlap(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    overlap = timedelta(minutes=15)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60), overlap=overlap)
    h.run()
    cutoff = (dt(h.state["last_stop"]) - overlap).timestamp()
    assert all(ts >= cutoff for ts in h.state["seen"].values())
    assert len(h.state["seen"]) < len(fixture_events)


def test_failure_keeps_progress_and_rerun_does_not_duplicate(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    backfill = now - oldest(fixture_events) + timedelta(hours=1)
    failing = FakeClient(fixture_events, fail_on_call=3)
    h = Harness(failing, now, logger, backfill=backfill)

    with pytest.raises(TransientError):
        h.run()
    assert len(h.saved) == 2  # two windows completed before the failure
    written_before = len(h.written)

    h.collector.client = FakeClient(fixture_events)
    h.run()
    hashes = [rec["event_hash"] for rec, _ in h.written]
    assert len(hashes) == len(set(hashes)) == len(fixture_events)
    assert written_before < len(fixture_events)


def test_events_without_timestamp_are_skipped(logger):
    now = dt("2026-10-30T12:00:00Z")

    class Client:
        def events(self, start, stop):
            return [{"eventid": 1, "msg": "no time"}, {"timestamp": "2026-10-30T11:00:00Z", "eventid": 2, "msg": "ok"}]

    h = Harness(Client(), now, logger, backfill=timedelta(hours=2), max_window=timedelta(days=1))
    assert h.run() == 1


def test_window_returning_exactly_the_cap_is_split(logger):
    now = dt("2026-10-30T12:00:00Z")
    calls = []

    class CappedClient:
        def events(self, start, stop):
            calls.append((start, stop))
            if len(calls) == 1:
                return [{"timestamp": "2026-10-30T11:00:00Z", "eventid": i, "msg": "x"} for i in range(RESPONSE_CAP)]
            return [{"timestamp": start + "Z", "eventid": len(calls), "msg": "part"}]

    h = Harness(CappedClient(), now, logger, backfill=timedelta(hours=2), max_window=timedelta(days=1))
    assert h.run() == 2
    assert len(calls) == 3
    assert calls[1][0] == calls[0][0] and calls[2][1] == calls[0][1]


def test_no_work_when_checkpoint_is_ahead_of_now(logger):
    now = dt("2026-10-30T12:00:00Z")
    h = Harness(FakeClient([]), now, logger, overlap=timedelta(0))
    h.state = Checkpoint(now + timedelta(hours=1)).to_dict()
    assert h.run() == 0
    assert h.saved == []


def test_corrupt_checkpoint_falls_back_to_backfill(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60))
    h.state = {"last_stop": "not a time"}
    assert h.run() == len(fixture_events)


# --- end to end against the mock server -----------------------------------


def test_collector_with_real_client_and_mock_server(mock_api, fixture_events, logger):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_api)
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(client, now, logger, backfill=timedelta(days=60))
    assert h.run() == len(fixture_events)
    h.now = now + timedelta(minutes=10)
    assert h.run() == 0
