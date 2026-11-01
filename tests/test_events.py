from datetime import datetime, timedelta, timezone

import pytest

from mock_api.server import DEFAULT_API_KEY, LEGACY_KEYS, filter_events, page_events
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


def test_event_hash_is_stable_when_the_api_adds_fields(fixture_events):
    """Upgrading the API must not change hashes, or the overlap duplicates."""
    for event in fixture_events[:20]:
        legacy = {k: event[k] for k in LEGACY_KEYS if k in event}
        assert event_hash(event) == event_hash(legacy)


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
    cp = Checkpoint(dt("2026-10-30T10:00:00Z"), {"abc": 1793354400}, since_id=42, skip_ids=[50, 44],
                    bootstrap_since_id=40)
    restored = Checkpoint.from_dict(cp.to_dict())
    assert restored.last_stop == cp.last_stop
    assert restored.seen == cp.seen
    assert restored.since_id == 42
    assert restored.skip_ids == [44, 50]
    assert restored.bootstrap_since_id == 40


def test_checkpoint_version_1_still_loads():
    cp = Checkpoint.from_dict({"version": 1, "last_stop": "2026-10-30T10:00:00", "seen": {"a": 1}})
    assert cp.last_stop == dt("2026-10-30T10:00:00Z")
    assert cp.since_id is None and cp.bootstrap_since_id is None and cp.skip_ids == []


@pytest.mark.parametrize("data", [None, "x", {}, {"last_stop": "garbage"}, [1, 2]])
def test_checkpoint_invalid_data_is_ignored(data):
    assert Checkpoint.from_dict(data) is None


def test_checkpoint_with_bad_fields_still_loads():
    cp = Checkpoint.from_dict({"last_stop": "2026-10-30T10:00:00", "seen": "nope", "since_id": "12",
                               "skip_ids": "x"})
    assert cp.seen == {} and cp.since_id is None and cp.skip_ids == []


# --- fakes ----------------------------------------------------------------


class FakeClient:
    """Serves events like the API, using the mock server's selection logic.

    legacy=True behaves like the API before ids existed.
    """

    def __init__(self, events, legacy=False, fail_on_call=None, on_call=None):
        self.data = [dict(e) for e in events]
        self.legacy = legacy
        if legacy:
            self.data = [{k: e[k] for k in LEGACY_KEYS if k in e} for e in self.data]
        self.calls = []
        self.fail_on_call = fail_on_call
        self.on_call = on_call

    def _record(self, call):
        self.calls.append(call)
        if self.on_call:
            self.on_call(self, len(self.calls))
        if self.fail_on_call is not None and len(self.calls) == self.fail_on_call:
            raise TransientError("boom")

    def insert(self, event):
        event = dict(event)
        if not self.legacy:
            event["id"] = max([e.get("id", 0) for e in self.data] + [0]) + 1
        self.data.append(event)
        return event

    def events(self, start, stop):
        self._record(("window", start, stop))
        return filter_events(self.data, {"start": start, "stop": stop})

    def events_latest(self):
        self._record(("latest",))
        return filter_events(self.data, {})

    def events_since(self, since_id, limit):
        self._record(("since", since_id, limit))
        if self.legacy:
            return filter_events(self.data, {}), None
        return page_events(self.data, since_id, limit)


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

    @property
    def client(self):
        return self.collector.client


def newest(events):
    return max(dt(e["timestamp"]) for e in events)


def oldest(events):
    return min(dt(e["timestamp"]) for e in events)


def full_backfill(events):
    return newest(events) - oldest(events) + timedelta(hours=1)


def late_event(ts, msg):
    return {"timestamp": format_ts(ts) + "Z", "eventid": 1, "level": 50, "source": "hosts", "msg": msg}


# --- window mode (API without ids) ----------------------------------------


def test_legacy_first_run_backfills_and_writes_sorted_events(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=full_backfill(fixture_events))

    assert h.run() == len(fixture_events) == len(h.written)
    times = [ts for _, ts in h.written]
    assert times == sorted(times)
    assert all(rec["event_hash"] == event_hash(rec) for rec, _ in h.written)
    assert h.state["last_stop"] == format_ts(now - timedelta(seconds=60))
    assert h.state["since_id"] is None


def test_legacy_backfill_limits_how_far_back_we_go(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=timedelta(days=2))
    h.run()
    expected = [e for e in fixture_events if dt(e["timestamp"]) >= now - timedelta(days=2)]
    assert len(h.written) == len(expected)


def test_written_timestamp_matches_event(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=timedelta(days=60))
    h.run()
    for record, ts in h.written:
        assert ts == dt(record["timestamp"]).timestamp()


def test_legacy_second_run_without_new_events_writes_nothing(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=timedelta(days=60))
    h.run()
    h.now = now + timedelta(minutes=5)
    assert h.run() == 0


def test_legacy_overlap_catches_late_event_without_duplicates(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=timedelta(days=60),
                overlap=timedelta(minutes=15))
    h.run()
    last_stop = dt(h.state["last_stop"])
    h.client.insert(late_event(last_stop - timedelta(minutes=10), "late event"))
    h.now = now + timedelta(minutes=5)

    assert h.run() == 1
    assert h.written[-1][0]["msg"] == "late event"


def test_legacy_event_later_than_overlap_is_missed(fixture_events, logger):
    """Documents the limit of window mode; id mode does not have it."""
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=timedelta(days=60),
                overlap=timedelta(minutes=15))
    h.run()
    h.client.insert(late_event(dt(h.state["last_stop"]) - timedelta(hours=2), "too late"))
    h.now = now + timedelta(minutes=5)
    assert h.run() == 0


def test_legacy_seen_hashes_are_pruned_to_overlap(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    overlap = timedelta(minutes=15)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=timedelta(days=60), overlap=overlap)
    h.run()
    cutoff = (dt(h.state["last_stop"]) - overlap).timestamp()
    assert all(ts >= cutoff for ts in h.state["seen"].values())
    assert len(h.state["seen"]) < len(fixture_events)


def test_legacy_failure_keeps_progress_and_rerun_does_not_duplicate(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True, fail_on_call=4), now, logger,
                backfill=full_backfill(fixture_events))

    with pytest.raises(TransientError):
        h.run()
    assert len(h.saved) == 2  # call 1 is the id probe, then two windows
    written_before = len(h.written)

    h.collector.client = FakeClient(fixture_events, legacy=True)
    h.run()
    hashes = [rec["event_hash"] for rec, _ in h.written]
    assert len(hashes) == len(set(hashes)) == len(fixture_events)
    assert written_before < len(fixture_events)


def test_events_without_timestamp_are_skipped_in_window_mode(logger):
    now = dt("2026-10-30T12:00:00Z")

    class Client:
        def events_latest(self):
            return [{"eventid": 9, "msg": "x"}]

        def events(self, start, stop):
            return [{"eventid": 1, "msg": "no time"}, {"timestamp": "2026-10-30T11:00:00Z", "eventid": 2, "msg": "ok"}]

    h = Harness(Client(), now, logger, backfill=timedelta(hours=2), max_window=timedelta(days=1))
    assert h.run() == 1


def test_window_returning_exactly_the_cap_is_split(logger):
    now = dt("2026-10-30T12:00:00Z")
    calls = []

    class CappedClient:
        def events_latest(self):
            return [{"eventid": 9, "msg": "no ids"}]

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
    h = Harness(FakeClient([], legacy=True), now, logger, overlap=timedelta(0))
    h.state = Checkpoint(now + timedelta(hours=1)).to_dict()
    h.client.data = [{"eventid": 1, "msg": "no ids", "timestamp": "2026-10-30T11:00:00Z", "level": 1,
                      "source": "x"}]
    assert h.run() == 0
    assert h.saved == []


def test_corrupt_checkpoint_falls_back_to_backfill(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=timedelta(days=60))
    h.state = {"last_stop": "not a time"}
    assert h.run() == len(fixture_events)


# --- id mode (API with since_id) ------------------------------------------


def ids_written(h):
    return [rec["id"] for rec, _ in h.written]


def test_first_run_backfills_then_switches_to_since_id(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=full_backfill(fixture_events))

    assert h.run() == len(fixture_events)
    assert sorted(ids_written(h)) == sorted(e["id"] for e in fixture_events)
    assert h.state["since_id"] == max(e["id"] for e in fixture_events)
    assert h.state["skip_ids"] == []
    assert all("event_hash" not in rec for rec, _ in h.written)


def test_backfill_only_covers_the_backfill_period(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=2))
    h.run()
    expected = {e["id"] for e in fixture_events if dt(e["timestamp"]) >= now - timedelta(days=2)}
    assert set(ids_written(h)) == expected


def test_second_run_uses_only_since_id(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60))
    h.run()
    h.client.calls.clear()
    h.now = now + timedelta(minutes=15)
    assert h.run() == 0
    assert [c[0] for c in h.client.calls] == ["since"]


def test_late_insert_with_old_timestamp_is_collected(fixture_events, logger):
    """The case window mode misses: a new row with an old timestamp."""
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60))
    h.run()
    h.client.insert(late_event(now - timedelta(days=3), "late insert"))
    h.now = now + timedelta(minutes=15)
    assert h.run() == 1
    assert h.written[-1][0]["msg"] == "late insert"


def test_events_inserted_during_backfill_are_written_exactly_once(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)

    def insert_during_backfill(client, call_number):
        if call_number == 3:
            # One inside a window that is still to come, one before the backfill.
            client.insert(late_event(now - timedelta(minutes=30), "new, recent"))
            client.insert(late_event(now - timedelta(days=90), "new, very old"))

    client = FakeClient(fixture_events, on_call=insert_during_backfill)
    h = Harness(client, now, logger, backfill=full_backfill(fixture_events))
    h.run()
    ids = ids_written(h)
    assert len(ids) == len(set(ids)) == len(fixture_events) + 2
    assert h.state["skip_ids"] == []


def test_paging_saves_checkpoint_per_page(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60), page_size=10)
    h.run()
    for i in range(35):
        h.client.insert(late_event(now, "burst {}".format(i)))
    h.saved.clear()
    h.now = now + timedelta(minutes=15)

    assert h.run() == 35
    assert len(h.saved) == 4
    assert [s["since_id"] for s in h.saved] == sorted(s["since_id"] for s in h.saved)
    assert ids_written(h)[-35:] == sorted(ids_written(h)[-35:])


def test_failure_while_paging_resumes_without_duplicates(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60), page_size=10)
    h.run()
    for i in range(35):
        h.client.insert(late_event(now, "burst {}".format(i)))
    h.client.calls.clear()
    h.client.fail_on_call = 3
    h.now = now + timedelta(minutes=15)

    with pytest.raises(TransientError):
        h.run()
    h.client.fail_on_call = None
    h.client.calls.clear()
    h.run()
    ids = ids_written(h)
    assert len(ids) == len(set(ids)) == len(fixture_events) + 35


def test_upgrade_from_window_checkpoint(fixture_events, logger):
    """A checkpoint written by window mode switches to id mode without duplicates."""
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events, legacy=True), now, logger, backfill=timedelta(days=60))
    h.run()
    written_legacy = len(h.written)

    # The API is upgraded: same events, now with ids and extra fields.
    h.collector.client = FakeClient(fixture_events)
    h.now = now + timedelta(minutes=15)
    assert h.run() == 0
    assert h.state["since_id"] == max(e["id"] for e in fixture_events)
    assert len(h.written) == written_legacy


def test_api_losing_since_id_falls_back_to_windows(fixture_events, logger):
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(FakeClient(fixture_events), now, logger, backfill=timedelta(days=60))
    h.run()
    h.collector.client = FakeClient(fixture_events, legacy=True)
    h.now = now + timedelta(minutes=15)
    assert h.run() == 0
    assert h.state["since_id"] is None
    h.now = now + timedelta(minutes=30)
    assert h.run() == 0  # next run is window mode from the last run, no duplicates


def test_full_page_without_progress_stops(logger):
    now = dt("2026-10-30T12:00:00Z")

    class StuckClient:
        def events_since(self, since_id, limit):
            return [{"id": since_id, "timestamp": "2026-10-30T11:00:00Z"}] * limit, since_id

    h = Harness(StuckClient(), now, logger, page_size=5)
    h.state = Checkpoint(now, since_id=100).to_dict()
    assert h.run() == 0


def test_event_without_timestamp_uses_index_time_in_id_mode(logger):
    now = dt("2026-10-30T12:00:00Z")

    class Client:
        def events_since(self, since_id, limit):
            return [{"id": 101, "msg": "no time"}], 101

    h = Harness(Client(), now, logger)
    h.state = Checkpoint(now, since_id=100).to_dict()
    assert h.run() == 1
    assert h.written[0][1] is None


def test_empty_account_starts_id_mode_at_zero(logger):
    now = dt("2026-10-30T12:00:00Z")
    h = Harness(FakeClient([]), now, logger, backfill=timedelta(days=1))
    assert h.run() == 0
    assert h.state["since_id"] == 0


# --- end to end against the mock server -----------------------------------


def test_collector_with_mock_v4(mock_server_v4, fixture_events, logger):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_server_v4.url)
    org_a = [e for e in fixture_events if e["organization"]["id"] == 1470062]
    now = newest(fixture_events) + timedelta(minutes=5)
    h = Harness(client, now, logger, backfill=timedelta(days=60))
    assert h.run() == len(org_a)

    mock_server_v4.api.insert(late_event(now - timedelta(days=5), "late insert"))
    h.now = now + timedelta(minutes=15)
    assert h.run() == 1


def test_collector_with_mock_legacy(mock_server_legacy, legacy_events, logger):
    client = ShadowTrackrClient(DEFAULT_API_KEY, base_url=mock_server_legacy.url)
    now = newest(legacy_events) + timedelta(minutes=5)
    h = Harness(client, now, logger, backfill=timedelta(days=60))
    assert h.run() == len(legacy_events)
    assert h.state["since_id"] is None
    h.now = now + timedelta(minutes=10)
    assert h.run() == 0
