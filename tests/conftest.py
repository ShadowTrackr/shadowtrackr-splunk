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


@pytest.fixture(scope="session")
def fixture_events():
    with open(os.path.join(FIXTURES, "events.json"), encoding="utf-8") as f:
        return json.load(f)["data"]


@pytest.fixture(scope="session")
def mock_api():
    """Run the mock API on a free port for the whole test session."""
    srv = mock_server.make_server("127.0.0.1", 0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address
    yield "http://{}:{}/api/v4".format(host, port)
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def logger():
    return logging.getLogger("shadowtrackr-test")
