"""Tests for the watch_epss tool and manus-agent watch CLI subcommand.

All tests are unit tests — zero real HTTP calls.  Network calls are replaced by
mocks/fakes throughout.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _make_tool_use(action: str, **extra: Any) -> dict:
    return {
        "toolUseId": "test-watch-001",
        "input": {"action": action, **extra},
    }


@pytest.fixture()
def watchlist_tmp(tmp_path: Path) -> Path:
    """Return a temporary watchlist file path (does not need to exist yet)."""
    return tmp_path / "watchlist.jsonl"


@pytest.fixture()
def watchlist_env(watchlist_tmp: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point MANUS_WATCHLIST_PATH to a temp file for the duration of the test."""
    monkeypatch.setenv("MANUS_WATCHLIST_PATH", str(watchlist_tmp))
    return watchlist_tmp


# Mock EPSS API responses
_MOCK_EPSS_SINGLE = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2024-3094", "epss": "0.8512", "percentile": "0.9970", "date": "2026-06-30"},
    ],
}

_MOCK_EPSS_MULTI = {
    "status": "OK",
    "data": [
        {"cve": "CVE-2024-3094", "epss": "0.9200", "percentile": "0.9980", "date": "2026-06-30"},
        {"cve": "CVE-2021-44228", "epss": "0.9750", "percentile": "0.9999", "date": "2026-06-30"},
    ],
}

# ---------------------------------------------------------------------------
# Module import tests
# ---------------------------------------------------------------------------


def test_watch_epss_module_imports():
    import manus_agent.tools.watch_epss as m

    assert hasattr(m, "watch_epss")
    assert hasattr(m, "TOOL_SPEC")


def test_tool_spec_required_fields():
    from manus_agent.tools.watch_epss import TOOL_SPEC

    assert TOOL_SPEC["name"] == "watch_epss"
    schema = TOOL_SPEC["inputSchema"]["json"]
    assert "action" in schema["properties"]
    assert "cve_id" in schema["properties"]
    assert "spike_threshold" in schema["properties"]
    assert schema["required"] == ["action"]


def test_tool_spec_action_enum():
    from manus_agent.tools.watch_epss import TOOL_SPEC

    enum_vals = TOOL_SPEC["inputSchema"]["json"]["properties"]["action"]["enum"]
    assert set(enum_vals) == {"add", "remove", "list", "check"}


# ---------------------------------------------------------------------------
# _resolve_path
# ---------------------------------------------------------------------------


def test_resolve_path_creates_parent(tmp_path: Path):
    from manus_agent.tools.watch_epss import _resolve_path

    deep = tmp_path / "a" / "b" / "c" / "watchlist.jsonl"
    result = _resolve_path(str(deep))
    assert result == deep
    assert deep.parent.exists()


def test_resolve_path_default_is_under_home():
    from manus_agent.tools.watch_epss import _DEFAULT_WATCHLIST_PATH, _resolve_path

    result = _resolve_path(None)
    assert result == _DEFAULT_WATCHLIST_PATH


# ---------------------------------------------------------------------------
# _load_watchlist / _save_watchlist
# ---------------------------------------------------------------------------


def test_load_empty_file_returns_empty_list(tmp_path: Path):
    from manus_agent.tools.watch_epss import _load_watchlist

    p = tmp_path / "empty.jsonl"
    assert _load_watchlist(p) == []


def test_load_nonexistent_returns_empty_list(tmp_path: Path):
    from manus_agent.tools.watch_epss import _load_watchlist

    assert _load_watchlist(tmp_path / "missing.jsonl") == []


def test_save_and_reload_records(tmp_path: Path):
    from manus_agent.tools.watch_epss import _load_watchlist, _save_watchlist

    p = tmp_path / "wl.jsonl"
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        },
        {
            "cve_id": "CVE-2021-44228",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        },
    ]
    _save_watchlist(p, records)
    loaded = _load_watchlist(p)
    assert len(loaded) == 2
    assert loaded[0]["cve_id"] == "CVE-2024-3094"
    assert loaded[1]["cve_id"] == "CVE-2021-44228"


def test_save_empty_list(tmp_path: Path):
    from manus_agent.tools.watch_epss import _load_watchlist, _save_watchlist

    p = tmp_path / "wl.jsonl"
    _save_watchlist(p, [])
    assert _load_watchlist(p) == []


def test_load_skips_corrupt_lines(tmp_path: Path):
    from manus_agent.tools.watch_epss import _load_watchlist

    p = tmp_path / "wl.jsonl"
    p.write_text('{"cve_id": "CVE-2024-3094"}\nNOT_JSON\n{"cve_id": "CVE-2021-44228"}\n')
    records = _load_watchlist(p)
    assert len(records) == 2


# ---------------------------------------------------------------------------
# _action_add
# ---------------------------------------------------------------------------


def test_action_add_new_cve(tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_add, _load_watchlist

    p = tmp_path / "wl.jsonl"
    records, msg = _action_add([], "CVE-2024-3094", p)
    assert len(records) == 1
    assert records[0]["cve_id"] == "CVE-2024-3094"
    assert "Added" in msg
    # Persisted
    assert len(_load_watchlist(p)) == 1


def test_action_add_normalises_to_uppercase(tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_add

    p = tmp_path / "wl.jsonl"
    records, _ = _action_add([], "cve-2024-3094", p)
    assert records[0]["cve_id"] == "CVE-2024-3094"


def test_action_add_duplicate_is_noop(tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_add

    p = tmp_path / "wl.jsonl"
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        }
    ]
    records, msg = _action_add(records, "CVE-2024-3094", p)
    assert len(records) == 1
    assert "already" in msg


def test_action_add_sets_added_at(tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_add

    p = tmp_path / "wl.jsonl"
    records, _ = _action_add([], "CVE-2024-3094", p)
    assert records[0]["added_at"] is not None


def test_action_add_multiple(tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_add

    p = tmp_path / "wl.jsonl"
    records: list[dict] = []
    records, _ = _action_add(records, "CVE-2024-3094", p)
    records, _ = _action_add(records, "CVE-2021-44228", p)
    assert len(records) == 2


# ---------------------------------------------------------------------------
# _action_remove
# ---------------------------------------------------------------------------


def test_action_remove_existing(tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_remove

    p = tmp_path / "wl.jsonl"
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        },
        {
            "cve_id": "CVE-2021-44228",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        },
    ]
    records, msg = _action_remove(records, "CVE-2024-3094", p)
    assert len(records) == 1
    assert records[0]["cve_id"] == "CVE-2021-44228"
    assert "Removed" in msg


def test_action_remove_not_found(tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_remove

    p = tmp_path / "wl.jsonl"
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        }
    ]
    records, msg = _action_remove(records, "CVE-9999-9999", p)
    assert len(records) == 1
    assert "not found" in msg


def test_action_remove_normalises_case(tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_remove

    p = tmp_path / "wl.jsonl"
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        }
    ]
    records, msg = _action_remove(records, "cve-2024-3094", p)
    assert len(records) == 0
    assert "Removed" in msg


# ---------------------------------------------------------------------------
# _action_list
# ---------------------------------------------------------------------------


def test_action_list_empty():
    from manus_agent.tools.watch_epss import _action_list

    msg = _action_list([])
    assert "empty" in msg.lower()


def test_action_list_with_entries():
    from manus_agent.tools.watch_epss import _action_list

    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": "2026-06-30",
            "last_epss": 0.8512,
            "baseline_epss": 0.8512,
        },
        {
            "cve_id": "CVE-2021-44228",
            "added_at": "2026-06-29",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        },
    ]
    msg = _action_list(records)
    assert "CVE-2024-3094" in msg
    assert "CVE-2021-44228" in msg
    assert "2" in msg  # "Watching 2 CVE(s)"


def test_action_list_shows_never_for_unchecked():
    from manus_agent.tools.watch_epss import _action_list

    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        }
    ]
    msg = _action_list(records)
    assert "never" in msg


def test_action_list_shows_last_epss():
    from manus_agent.tools.watch_epss import _action_list

    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": "2026-06-30",
            "last_epss": 0.8512,
            "baseline_epss": 0.8512,
        }
    ]
    msg = _action_list(records)
    assert "0.8512" in msg


# ---------------------------------------------------------------------------
# _action_check
# ---------------------------------------------------------------------------


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_action_check_empty_watchlist(mock_fetch, tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_check

    records, msg = _action_check([], tmp_path / "wl.jsonl", 0.10)
    assert "empty" in msg.lower()
    mock_fetch.assert_not_called()


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_action_check_first_check_sets_scores(mock_fetch, tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_check

    mock_fetch.return_value = {"CVE-2024-3094": 0.8512}
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        }
    ]
    updated, msg = _action_check(records, tmp_path / "wl.jsonl", 0.10)
    assert updated[0]["last_epss"] == pytest.approx(0.8512)
    assert updated[0]["baseline_epss"] == pytest.approx(0.8512)
    assert "first check" in msg


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_action_check_no_spike(mock_fetch, tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_check

    mock_fetch.return_value = {"CVE-2024-3094": 0.8600}
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": "2026-06-29",
            "last_epss": 0.8512,
            "baseline_epss": 0.8512,
        }
    ]
    updated, msg = _action_check(records, tmp_path / "wl.jsonl", 0.10)
    assert "spike" not in msg.lower() or "🚨" not in msg
    assert updated[0]["last_epss"] == pytest.approx(0.8600)


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_action_check_spike_detected(mock_fetch, tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_check

    mock_fetch.return_value = {"CVE-2024-3094": 0.9600}  # was 0.85, now 0.96 → delta 0.11
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": "2026-06-29",
            "last_epss": 0.85,
            "baseline_epss": 0.85,
        }
    ]
    updated, msg = _action_check(records, tmp_path / "wl.jsonl", 0.10)
    assert "⚠️" in msg or "spike" in msg.lower() or "🚨" in msg


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_action_check_custom_threshold(mock_fetch, tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_check

    # delta = 0.06; threshold 0.05 → should spike
    mock_fetch.return_value = {"CVE-2024-3094": 0.91}
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": "2026-06-29",
            "last_epss": 0.85,
            "baseline_epss": 0.85,
        }
    ]
    _, msg = _action_check(records, tmp_path / "wl.jsonl", 0.05)
    assert "⚠️" in msg or "🚨" in msg


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_action_check_persists_scores(mock_fetch, tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_check, _load_watchlist

    p = tmp_path / "wl.jsonl"
    mock_fetch.return_value = {"CVE-2024-3094": 0.9200}
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        }
    ]
    _action_check(records, p, 0.10)
    reloaded = _load_watchlist(p)
    assert reloaded[0]["last_epss"] == pytest.approx(0.9200)


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_action_check_handles_api_error(mock_fetch, tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_check

    mock_fetch.return_value = {"CVE-2024-3094": -1.0}  # sentinel for error
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-30",
            "last_checked": None,
            "last_epss": None,
            "baseline_epss": None,
        }
    ]
    updated, msg = _action_check(records, tmp_path / "wl.jsonl", 0.10)
    assert "failed" in msg.lower() or "error" in msg.lower() or "⚡" in msg


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_action_check_multiple_cves(mock_fetch, tmp_path: Path):
    from manus_agent.tools.watch_epss import _action_check

    mock_fetch.return_value = {
        "CVE-2024-3094": 0.9200,
        "CVE-2021-44228": 0.9750,
    }
    records = [
        {
            "cve_id": "CVE-2024-3094",
            "added_at": "2026-06-29",
            "last_checked": "2026-06-29",
            "last_epss": 0.85,
            "baseline_epss": 0.85,
        },
        {
            "cve_id": "CVE-2021-44228",
            "added_at": "2026-06-29",
            "last_checked": "2026-06-29",
            "last_epss": 0.97,
            "baseline_epss": 0.97,
        },
    ]
    updated, msg = _action_check(records, tmp_path / "wl.jsonl", 0.10)
    assert len(updated) == 2
    assert "CVE-2024-3094" in msg or "CVE-2021-44228" in msg


# ---------------------------------------------------------------------------
# _fetch_current_epss unit tests
# ---------------------------------------------------------------------------


def test_fetch_current_epss_empty_list():
    from manus_agent.tools.watch_epss import _fetch_current_epss

    result = _fetch_current_epss([])
    assert result == {}


@patch("manus_agent.tools.watch_epss.requests.get")
def test_fetch_current_epss_happy_path(mock_get):
    from unittest.mock import MagicMock

    from manus_agent.tools.watch_epss import _fetch_current_epss

    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = _MOCK_EPSS_SINGLE
    mock_get.return_value = resp

    result = _fetch_current_epss(["CVE-2024-3094"])
    assert "CVE-2024-3094" in result
    assert abs(result["CVE-2024-3094"] - 0.8512) < 1e-4


@patch("manus_agent.tools.watch_epss.requests.get")
def test_fetch_current_epss_multi_cve(mock_get):
    from unittest.mock import MagicMock

    from manus_agent.tools.watch_epss import _fetch_current_epss

    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = _MOCK_EPSS_MULTI
    mock_get.return_value = resp

    result = _fetch_current_epss(["CVE-2024-3094", "CVE-2021-44228"])
    assert len(result) == 2
    assert abs(result["CVE-2021-44228"] - 0.9750) < 1e-4


@patch("manus_agent.tools.watch_epss.requests.get")
def test_fetch_current_epss_network_error(mock_get):
    import requests as req_mod

    from manus_agent.tools.watch_epss import _fetch_current_epss

    mock_get.side_effect = req_mod.exceptions.ConnectionError("down")
    result = _fetch_current_epss(["CVE-2024-3094"])
    assert result["CVE-2024-3094"] == -1.0


@patch("manus_agent.tools.watch_epss.requests.get")
def test_fetch_current_epss_missing_cve_defaults_to_minus_one(mock_get):
    from unittest.mock import MagicMock

    from manus_agent.tools.watch_epss import _fetch_current_epss

    # API returns empty data
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"status": "OK", "data": []}
    mock_get.return_value = resp

    result = _fetch_current_epss(["CVE-9999-9999"])
    assert result["CVE-9999-9999"] == -1.0


# ---------------------------------------------------------------------------
# watch_epss tool function — integration tests (all mocked)
# ---------------------------------------------------------------------------


def test_tool_invalid_action(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    result = watch_epss(_make_tool_use("bogus"))
    assert result["status"] == "error"
    assert "Unknown action" in result["content"][0]["text"]


def test_tool_add_invalid_cve(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    result = watch_epss(_make_tool_use("add", cve_id="NOTACVE"))
    assert result["status"] == "error"
    assert "Invalid CVE ID" in result["content"][0]["text"]


def test_tool_remove_invalid_cve(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    result = watch_epss(_make_tool_use("remove", cve_id="BAD"))
    assert result["status"] == "error"
    assert "Invalid CVE ID" in result["content"][0]["text"]


def test_tool_add_success(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    result = watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    assert result["status"] == "success"
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["count"] == 1
    assert json_block["action"] == "add"


def test_tool_add_then_list(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    result = watch_epss(_make_tool_use("list"))
    assert result["status"] == "success"
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["count"] == 1
    text = next(c["text"] for c in result["content"] if "text" in c)
    assert "CVE-2024-3094" in text


def test_tool_list_empty(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    result = watch_epss(_make_tool_use("list"))
    assert result["status"] == "success"
    text = next(c["text"] for c in result["content"] if "text" in c)
    assert "empty" in text.lower()


def test_tool_add_duplicate_returns_success_with_message(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    result = watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    assert result["status"] == "success"
    text = next(c["text"] for c in result["content"] if "text" in c)
    assert "already" in text


def test_tool_remove_success(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    result = watch_epss(_make_tool_use("remove", cve_id="CVE-2024-3094"))
    assert result["status"] == "success"
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["count"] == 0


def test_tool_remove_not_found(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    result = watch_epss(_make_tool_use("remove", cve_id="CVE-9999-9999"))
    assert result["status"] == "success"
    text = next(c["text"] for c in result["content"] if "text" in c)
    assert "not found" in text


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_tool_check_empty(mock_fetch, watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    result = watch_epss(_make_tool_use("check"))
    assert result["status"] == "success"
    mock_fetch.assert_not_called()


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_tool_check_with_entries(mock_fetch, watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    mock_fetch.return_value = {"CVE-2024-3094": 0.8512}
    watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    result = watch_epss(_make_tool_use("check"))
    assert result["status"] == "success"
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["count"] == 1
    assert json_block["records"][0]["last_epss"] == pytest.approx(0.8512)


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_tool_check_json_content(mock_fetch, watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    mock_fetch.return_value = {"CVE-2024-3094": 0.8512}
    watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    result = watch_epss(_make_tool_use("check"))
    json_block = next(c["json"] for c in result["content"] if "json" in c)
    assert json_block["action"] == "check"
    assert "watchlist_path" in json_block
    assert isinstance(json_block["records"], list)


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_tool_check_spike_detected_in_text(mock_fetch, watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    # Prime the watchlist with a previous score
    watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    # Simulate first check to set last_epss = 0.80
    mock_fetch.return_value = {"CVE-2024-3094": 0.80}
    watch_epss(_make_tool_use("check"))
    # Second check: score jumps to 0.91 (delta 0.11 > threshold 0.10)
    mock_fetch.return_value = {"CVE-2024-3094": 0.91}
    result = watch_epss(_make_tool_use("check"))
    text = next(c["text"] for c in result["content"] if "text" in c)
    assert "⚠️" in text or "🚨" in text


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_tool_check_custom_spike_threshold(mock_fetch, watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    mock_fetch.return_value = {"CVE-2024-3094": 0.80}
    watch_epss(_make_tool_use("check"))
    # delta 0.06; default threshold 0.10 → no spike; custom 0.05 → spike
    mock_fetch.return_value = {"CVE-2024-3094": 0.86}
    result = watch_epss(_make_tool_use("check", spike_threshold=0.05))
    text = next(c["text"] for c in result["content"] if "text" in c)
    assert "⚠️" in text or "🚨" in text


def test_tool_result_always_has_text_and_json(watchlist_env: Path):
    from manus_agent.tools.watch_epss import watch_epss

    result = watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094"))
    content_keys = [list(c.keys())[0] for c in result["content"]]
    assert "text" in content_keys
    assert "json" in content_keys


def test_tool_watchlist_path_override(tmp_path: Path):
    """watchlist_path parameter overrides the default location."""
    from manus_agent.tools.watch_epss import watch_epss

    custom_path = str(tmp_path / "custom" / "wl.jsonl")
    result = watch_epss(_make_tool_use("add", cve_id="CVE-2024-3094", watchlist_path=custom_path))
    assert result["status"] == "success"
    assert Path(custom_path).exists()


# ---------------------------------------------------------------------------
# CLI subcommand: manus-agent watch
# ---------------------------------------------------------------------------


def test_watch_subcommand_registered():
    from manus_agent.cli import _SUBCOMMANDS

    assert "watch" in _SUBCOMMANDS


def test_watch_parser_help_exits_zero():
    from manus_agent.cli import _build_watch_parser

    parser = _build_watch_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0


def test_watch_parser_no_subcommand_exits_nonzero():
    from manus_agent.cli import _build_watch_parser

    parser = _build_watch_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args([])
    assert exc_info.value.code != 0


def test_watch_add_parser():
    from manus_agent.cli import _build_watch_parser

    parser = _build_watch_parser()
    args = parser.parse_args(["add", "CVE-2024-3094"])
    assert args.watch_action == "add"
    assert args.cve_id == "CVE-2024-3094"


def test_watch_remove_parser():
    from manus_agent.cli import _build_watch_parser

    parser = _build_watch_parser()
    args = parser.parse_args(["remove", "CVE-2024-3094"])
    assert args.watch_action == "remove"
    assert args.cve_id == "CVE-2024-3094"


def test_watch_list_parser():
    from manus_agent.cli import _build_watch_parser

    parser = _build_watch_parser()
    args = parser.parse_args(["list"])
    assert args.watch_action == "list"


def test_watch_check_parser_defaults():
    from manus_agent.cli import _build_watch_parser

    parser = _build_watch_parser()
    args = parser.parse_args(["check"])
    assert args.watch_action == "check"
    assert args.threshold == pytest.approx(0.10)
    assert args.output == "text"


def test_watch_check_parser_custom_threshold():
    from manus_agent.cli import _build_watch_parser

    parser = _build_watch_parser()
    args = parser.parse_args(["check", "--threshold", "0.05"])
    assert args.threshold == pytest.approx(0.05)


def test_watch_check_parser_json_output():
    from manus_agent.cli import _build_watch_parser

    parser = _build_watch_parser()
    args = parser.parse_args(["check", "--output", "json"])
    assert args.output == "json"


def test_run_watch_add(watchlist_env: Path, capsys):
    from manus_agent.cli import _run_watch

    rc = _run_watch(["add", "CVE-2024-3094"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2024-3094" in out


def test_run_watch_list_empty(watchlist_env: Path, capsys):
    from manus_agent.cli import _run_watch

    rc = _run_watch(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "empty" in out.lower()


def test_run_watch_list_with_entry(watchlist_env: Path, capsys):
    from manus_agent.cli import _run_watch

    _run_watch(["add", "CVE-2024-3094"])
    capsys.readouterr()  # clear
    rc = _run_watch(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2024-3094" in out


def test_run_watch_remove(watchlist_env: Path, capsys):
    from manus_agent.cli import _run_watch

    _run_watch(["add", "CVE-2024-3094"])
    capsys.readouterr()
    rc = _run_watch(["remove", "CVE-2024-3094"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Removed" in out


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_run_watch_check_text(mock_fetch, watchlist_env: Path, capsys):
    from manus_agent.cli import _run_watch

    mock_fetch.return_value = {"CVE-2024-3094": 0.8512}
    _run_watch(["add", "CVE-2024-3094"])
    capsys.readouterr()
    rc = _run_watch(["check"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2024-3094" in out or "check" in out.lower()


@patch("manus_agent.tools.watch_epss._fetch_current_epss")
def test_run_watch_check_json(mock_fetch, watchlist_env: Path, capsys):
    from manus_agent.cli import _run_watch

    mock_fetch.return_value = {"CVE-2024-3094": 0.8512}
    _run_watch(["add", "CVE-2024-3094"])
    capsys.readouterr()
    rc = _run_watch(["check", "--output", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["action"] == "check"
    assert data["count"] == 1
    assert isinstance(data["records"], list)


def test_run_watch_add_json_output(watchlist_env: Path, capsys):
    from manus_agent.cli import _run_watch

    rc = _run_watch(["add", "CVE-2024-3094", "--output", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["count"] == 1
    assert data["action"] == "add"


def test_run_watch_remove_json_output(watchlist_env: Path, capsys):
    from manus_agent.cli import _run_watch

    _run_watch(["add", "CVE-2024-3094"])
    capsys.readouterr()
    rc = _run_watch(["remove", "CVE-2024-3094", "--output", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["count"] == 0


# ---------------------------------------------------------------------------
# README coverage
# ---------------------------------------------------------------------------


def test_readme_documents_watch():
    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "manus-agent watch" in content, "README must mention manus-agent watch"


def test_readme_watch_has_subcommands():
    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "watch add" in content
    assert "watch remove" in content
    assert "watch list" in content
    assert "watch check" in content


def test_readme_watch_documents_threshold():
    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "--threshold" in content


def test_readme_watch_in_toc():
    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    # TOC entry (anchor link)
    assert "watch" in content


def test_readme_watch_in_quick_reference():
    readme = Path(__file__).resolve().parents[1] / "README.md"
    content = readme.read_text()
    assert "watch check" in content


# ---------------------------------------------------------------------------
# vi_agent integration
# ---------------------------------------------------------------------------


def test_vi_agent_system_prompt_references_watch_epss():
    """The VI agent system prompt must mention watch_epss (Step 6d)."""
    from manus_agent.agents.vi_agent import SYSTEM_PROMPT

    assert "watch_epss" in SYSTEM_PROMPT
    assert "Step 6d" in SYSTEM_PROMPT


def test_watch_epss_tool_is_importable():
    from manus_agent.tools.watch_epss import TOOL_SPEC, watch_epss

    assert callable(watch_epss)
    assert TOOL_SPEC["name"] == "watch_epss"
