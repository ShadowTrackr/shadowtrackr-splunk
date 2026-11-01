import json
import logging
import os
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "package", "bin"))
sys.path.insert(0, ROOT)

from mock_api import server as mock_server  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def _fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return json.load(f)["data"]


@pytest.fixture(scope="session")
def fixture_events():
    """Events as the v4 API returns them (with ids and structured fields)."""
    return _fixture("events.json")


@pytest.fixture(scope="session")
def legacy_events(fixture_events):
    """The same events as the API returned them before the v4 changes."""
    return [{k: e[k] for k in mock_server.LEGACY_KEYS if k in e} for e in fixture_events]


@pytest.fixture(scope="session")
def fixture_event_types():
    return _fixture("event_types.json")


def _start(legacy):
    srv = mock_server.make_server("127.0.0.1", 0, legacy=legacy)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address
    srv.url = "http://{}:{}/api/v4".format(host, port)
    return srv


@pytest.fixture
def mock_server_v4():
    """A fresh v4 mock per test, so tests can insert events."""
    srv = _start(legacy=False)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def mock_server_legacy():
    srv = _start(legacy=True)
    yield srv
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def mock_api(mock_server_v4):
    return mock_server_v4.url


@pytest.fixture
def mock_api_legacy(mock_server_legacy):
    return mock_server_legacy.url


@pytest.fixture
def logger():
    return logging.getLogger("shadowtrackr-test")
