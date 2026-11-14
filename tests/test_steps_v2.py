"""Tests for reading the day's step count from the v2 diary."""

from datetime import date

import pytest

from myfitnesspal_mcp import server
from test_diary_v2 import FakeClient, FakeResponse, FakeSession

DAY = date(2026, 11, 14)


def steps_item(steps, calories, primary=True):
    return {
        "type": "steps_aggregate",
        "date": "2026-11-14",
        "steps": steps,
        "energy": {"unit": "calories", "value": calories},
        "primary": primary,
    }


def test_reads_steps_aggregate_for_the_day():
    session = FakeSession(get=FakeResponse(200, {"items": [steps_item(7964, 206)]}))
    result = server.get_steps_v2(FakeClient(session), DAY)
    assert result == {"date": "2026-11-14", "steps": 7964, "calories": 206}
    method, url, kwargs = session.calls[0]
    assert method == "GET" and url.endswith("/v2/diary")
    assert kwargs["params"] == {"entry_date": "2026-11-14", "types": "steps_aggregate"}
    assert kwargs["headers"]["Authorization"] == "Bearer token-123"


def test_no_steps_synced_gives_nulls():
    session = FakeSession(get=FakeResponse(200, {"items": []}))
    assert server.get_steps_v2(FakeClient(session), DAY) == {
        "date": "2026-11-14",
        "steps": None,
        "calories": None,
    }


def test_primary_source_wins_over_a_bigger_secondary_one():
    items = [steps_item(12000, 300, primary=False), steps_item(8000, 200, primary=True)]
    session = FakeSession(get=FakeResponse(200, {"items": items}))
    assert server.get_steps_v2(FakeClient(session), DAY)["steps"] == 8000


def test_other_item_types_are_ignored():
    items = [{"type": "exercise_entry", "steps": 5}, steps_item(2603, 42)]
    session = FakeSession(get=FakeResponse(200, {"items": items}))
    assert server.get_steps_v2(FakeClient(session), DAY)["steps"] == 2603


def test_http_error_raises():
    session = FakeSession(get=FakeResponse(401, {}))
    with pytest.raises(RuntimeError):
        server.get_steps_v2(FakeClient(session), DAY)
