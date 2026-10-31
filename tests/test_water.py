"""Tests for water read/write: MFP stores water in millilitres."""

import asyncio
import json
import os
import sys
from datetime import date
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from myfitnesspal_mcp import server  # noqa: E402


def _client(page_html='<meta name="csrf-token" content="tok123">'):
    client = MagicMock()
    client.BASE_URL_SECURE = "https://www.myfitnesspal.com/"
    page = MagicMock(text=page_html)
    page.raise_for_status.return_value = None
    client.session.get.return_value = page
    resp = MagicMock(status_code=200)
    resp.raise_for_status.return_value = None
    client.session.post.return_value = resp
    return client


class TestSetWaterIntake:
    def test_posts_ml_to_food_water_with_csrf_header(self):
        client = _client()
        server.set_water_intake(client, date(2026, 10, 31), 1300)

        url = client.session.post.call_args.args[0]
        kwargs = client.session.post.call_args.kwargs
        assert url == "https://www.myfitnesspal.com/food/water"
        assert kwargs["data"] == {"milliliters": 1300, "date": "2026-10-31"}
        assert kwargs["headers"]["X-CSRF-Token"] == "tok123"

    def test_missing_csrf_meta_raises(self):
        client = _client(page_html="<html></html>")
        with pytest.raises(RuntimeError, match="csrf-token"):
            server.set_water_intake(client, date(2026, 10, 31), 500)


class TestSetWaterInput:
    def test_requires_exactly_one_amount(self):
        with pytest.raises(ValidationError):
            server.SetWaterInput()
        with pytest.raises(ValidationError):
            server.SetWaterInput(milliliters=500, cups=2)

    def test_accepts_either(self):
        assert server.SetWaterInput(milliliters=1300).milliliters == 1300
        assert server.SetWaterInput(cups=2).cups == 2


class TestWaterTools:
    def test_set_water_ml_passes_through(self):
        client = _client()
        with patch.object(server, "get_mfp_client", return_value=client):
            out = json.loads(asyncio.run(server.mfp_set_water(
                server.SetWaterInput(milliliters=1300, date="2026-10-31"))))
        assert out["water_ml"] == 1300
        assert client.session.post.call_args.kwargs["data"]["milliliters"] == 1300

    def test_set_water_cups_converted(self):
        client = _client()
        with patch.object(server, "get_mfp_client", return_value=client):
            out = json.loads(asyncio.run(server.mfp_set_water(
                server.SetWaterInput(cups=2, date="2026-10-31"))))
        assert out["water_ml"] == pytest.approx(473.18)

    def test_get_water_returns_raw_ml(self):
        client = MagicMock()
        client.get_date.return_value = MagicMock(water=1300.0)
        with patch.object(server, "get_mfp_client", return_value=client):
            out = json.loads(asyncio.run(server.mfp_get_water(
                server.GetWaterInput(date="2026-10-31"))))
        assert out == {"date": "2026-10-31", "water_ml": 1300.0}
