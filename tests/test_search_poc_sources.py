"""Tests for search_poc_sources — multi-source PoC aggregator."""

from __future__ import annotations

import csv
import io
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_url_response(payload: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    resp.status = status
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _patch_urlopen(payload: dict):
    return patch(
        "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
        return_value=_make_url_response(payload),
    )


# ---------------------------------------------------------------------------
# _normalize_url
# ---------------------------------------------------------------------------


class TestNormalizeUrl:
    def test_strips_trailing_slash(self):
        from manus_agent.tools.search_poc_sources import _normalize_url

        assert _normalize_url("https://example.com/foo/") == "https://example.com/foo"

    def test_strips_dot_git(self):
        from manus_agent.tools.search_poc_sources import _normalize_url

        assert _normalize_url("https://github.com/user/repo.git") == "https://github.com/user/repo"

    def test_lowercases(self):
        from manus_agent.tools.search_poc_sources import _normalize_url

        assert _normalize_url("HTTPS://EXAMPLE.COM") == "https://example.com"

    def test_strips_both(self):
        from manus_agent.tools.search_poc_sources import _normalize_url

        assert _normalize_url("HTTPS://GitHub.com/u/r.git/") == "https://github.com/u/r"

    def test_empty_string(self):
        from manus_agent.tools.search_poc_sources import _normalize_url

        assert _normalize_url("") == ""


# ---------------------------------------------------------------------------
# _parse_date
# ---------------------------------------------------------------------------


class TestParseDate:
    def test_date_only(self):
        from manus_agent.tools.search_poc_sources import _parse_date

        dt = _parse_date("2024-03-29")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 3
        assert dt.day == 29

    def test_datetime_with_z(self):
        from manus_agent.tools.search_poc_sources import _parse_date

        dt = _parse_date("2024-03-29T12:00:00Z")
        assert dt is not None

    def test_datetime_without_z(self):
        from manus_agent.tools.search_poc_sources import _parse_date

        dt = _parse_date("2024-03-29T12:00:00")
        assert dt is not None

    def test_none_input(self):
        from manus_agent.tools.search_poc_sources import _parse_date

        assert _parse_date(None) is None

    def test_garbage_input(self):
        from manus_agent.tools.search_poc_sources import _parse_date

        assert _parse_date("not-a-date") is None


# ---------------------------------------------------------------------------
# _is_recent
# ---------------------------------------------------------------------------


class TestIsRecent:
    def test_recent_date(self):
        from datetime import datetime, timezone

        from manus_agent.tools.search_poc_sources import _is_recent

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert _is_recent(today) is True

    def test_old_date(self):
        from manus_agent.tools.search_poc_sources import _is_recent

        assert _is_recent("2020-01-01") is False

    def test_none_date(self):
        from manus_agent.tools.search_poc_sources import _is_recent

        assert _is_recent(None) is False


# ---------------------------------------------------------------------------
# _fetch_trickest
# ---------------------------------------------------------------------------


class TestFetchTrickest:
    def test_returns_result_when_cve_found(self):
        from manus_agent.tools.search_poc_sources import _fetch_trickest

        tree_payload = {
            "tree": [
                {"path": "2024", "type": "tree", "sha": "abc123"},
            ]
        }
        year_payload = {
            "tree": [
                {"path": "CVE-2024-3094", "type": "tree", "sha": "def456"},
            ]
        }
        responses = [
            _make_url_response(tree_payload),
            _make_url_response(year_payload),
        ]
        with patch(
            "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
            side_effect=responses,
        ):
            results = _fetch_trickest("CVE-2024-3094")

        assert len(results) == 1
        assert results[0]["source"] == "trickest"
        assert "CVE-2024-3094" in results[0]["url"]
        assert results[0]["exploited_in_wild"] is False

    def test_returns_empty_when_year_not_in_tree(self):
        from manus_agent.tools.search_poc_sources import _fetch_trickest

        tree_payload = {"tree": [{"path": "2023", "type": "tree", "sha": "abc"}]}
        with patch(
            "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
            return_value=_make_url_response(tree_payload),
        ):
            results = _fetch_trickest("CVE-2024-3094")
        assert results == []

    def test_returns_empty_when_cve_not_in_year(self):
        from manus_agent.tools.search_poc_sources import _fetch_trickest

        tree_payload = {"tree": [{"path": "2024", "type": "tree", "sha": "abc"}]}
        year_payload = {"tree": [{"path": "CVE-2024-0001", "type": "tree"}]}
        responses = [
            _make_url_response(tree_payload),
            _make_url_response(year_payload),
        ]
        with patch(
            "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
            side_effect=responses,
        ):
            results = _fetch_trickest("CVE-2024-3094")
        assert results == []

    def test_returns_empty_on_network_error(self):
        from manus_agent.tools.search_poc_sources import _fetch_trickest

        with patch(
            "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
            side_effect=OSError("network down"),
        ):
            results = _fetch_trickest("CVE-2024-3094")
        assert results == []

    def test_returns_empty_on_invalid_cve(self):
        from manus_agent.tools.search_poc_sources import _fetch_trickest

        results = _fetch_trickest("NOT-A-CVE")
        assert results == []

    def test_case_insensitive_cve_match(self):
        from manus_agent.tools.search_poc_sources import _fetch_trickest

        tree_payload = {"tree": [{"path": "2024", "type": "tree", "sha": "abc"}]}
        year_payload = {"tree": [{"path": "CVE-2024-3094", "type": "tree"}]}
        responses = [
            _make_url_response(tree_payload),
            _make_url_response(year_payload),
        ]
        with patch(
            "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
            side_effect=responses,
        ):
            results = _fetch_trickest("cve-2024-3094")
        assert len(results) == 1


# ---------------------------------------------------------------------------
# _fetch_vulncheck_kev
# ---------------------------------------------------------------------------


class TestFetchVulncheckKev:
    def test_skips_without_api_key(self):
        from manus_agent.tools.search_poc_sources import _fetch_vulncheck_kev

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("VULNCHECK_API_KEY", None)
            results = _fetch_vulncheck_kev("CVE-2024-3094")
        assert results == []

    def test_returns_kev_entry_when_matched(self):
        from manus_agent.tools.search_poc_sources import _fetch_vulncheck_kev

        payload = {
            "data": [
                {
                    "cveID": "CVE-2024-3094",
                    "dateAdded": "2024-03-29",
                    "sources": ["CISA KEV", "FBI Flash"],
                    "ransomwareUse": False,
                }
            ]
        }
        with patch.dict(os.environ, {"VULNCHECK_API_KEY": "testkey"}):
            with _patch_urlopen(payload):
                results = _fetch_vulncheck_kev("CVE-2024-3094")

        assert len(results) == 1
        assert results[0]["source"] == "vulncheck_kev"
        assert results[0]["exploited_in_wild"] is True
        assert results[0]["published"] == "2024-03-29"
        assert "kev" in results[0]["tags"]

    def test_ransomware_tag_added(self):
        from manus_agent.tools.search_poc_sources import _fetch_vulncheck_kev

        payload = {
            "data": [
                {
                    "cveID": "CVE-2024-3094",
                    "dateAdded": "2024-03-29",
                    "sources": [],
                    "ransomwareUse": True,
                }
            ]
        }
        with patch.dict(os.environ, {"VULNCHECK_API_KEY": "testkey"}):
            with _patch_urlopen(payload):
                results = _fetch_vulncheck_kev("CVE-2024-3094")

        assert "ransomware" in results[0]["tags"]

    def test_returns_empty_when_no_matching_cve(self):
        from manus_agent.tools.search_poc_sources import _fetch_vulncheck_kev

        payload = {
            "data": [{"cveID": "CVE-2024-9999", "dateAdded": "2024-01-01", "sources": [], "ransomwareUse": False}]
        }
        with patch.dict(os.environ, {"VULNCHECK_API_KEY": "testkey"}):
            with _patch_urlopen(payload):
                results = _fetch_vulncheck_kev("CVE-2024-3094")
        assert results == []

    def test_returns_empty_on_network_error(self):
        from manus_agent.tools.search_poc_sources import _fetch_vulncheck_kev

        with patch.dict(os.environ, {"VULNCHECK_API_KEY": "testkey"}):
            with patch(
                "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
                side_effect=OSError("timeout"),
            ):
                results = _fetch_vulncheck_kev("CVE-2024-3094")
        assert results == []

    def test_empty_data_returns_empty(self):
        from manus_agent.tools.search_poc_sources import _fetch_vulncheck_kev

        payload = {"data": []}
        with patch.dict(os.environ, {"VULNCHECK_API_KEY": "testkey"}):
            with _patch_urlopen(payload):
                results = _fetch_vulncheck_kev("CVE-2024-3094")
        assert results == []


# ---------------------------------------------------------------------------
# _fetch_exploitdb
# ---------------------------------------------------------------------------


class TestFetchExploitdb:
    def _make_csv_content(self, entries: list[dict]) -> bytes:
        """Build a minimal Exploit-DB CSV with only the columns we need."""
        fieldnames = ["id", "description", "date_published", "author", "type", "platform", "codes"]
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for e in entries:
            writer.writerow(e)
        return buf.getvalue().encode()

    def test_returns_match(self, tmp_path):
        from manus_agent.tools.search_poc_sources import _fetch_exploitdb

        csv_data = self._make_csv_content(
            [
                {
                    "id": "42",
                    "description": "XZ Utils backdoor",
                    "date_published": "2024-04-01",
                    "author": "researcher",
                    "type": "remote",
                    "platform": "linux",
                    "codes": "CVE-2024-3094",
                },
            ]
        )
        cache = str(tmp_path / "exploitdb_cache.csv")
        with open(cache, "wb") as f:
            f.write(csv_data)
        with patch("manus_agent.tools.search_poc_sources._EXPLOITDB_CACHE", cache):
            with patch("manus_agent.tools.search_poc_sources.time.time", return_value=time.time()):
                results = _fetch_exploitdb("CVE-2024-3094")

        assert len(results) == 1
        assert results[0]["source"] == "exploitdb"
        assert "exploit-db.com/exploits/42" in results[0]["url"]
        assert results[0]["exploited_in_wild"] is False

    def test_no_match_returns_empty(self, tmp_path):
        from manus_agent.tools.search_poc_sources import _fetch_exploitdb

        csv_data = self._make_csv_content(
            [
                {
                    "id": "1",
                    "description": "Other vuln",
                    "date_published": "2024-01-01",
                    "author": "x",
                    "type": "local",
                    "platform": "windows",
                    "codes": "CVE-2020-0001",
                },
            ]
        )
        cache = str(tmp_path / "exploitdb_cache.csv")
        with open(cache, "wb") as f:
            f.write(csv_data)
        with patch("manus_agent.tools.search_poc_sources._EXPLOITDB_CACHE", cache):
            with patch("manus_agent.tools.search_poc_sources.time.time", return_value=time.time()):
                results = _fetch_exploitdb("CVE-2024-3094")

        assert results == []

    def test_downloads_when_cache_missing(self, tmp_path):
        from manus_agent.tools.search_poc_sources import _ensure_exploitdb_cache

        cache = str(tmp_path / "missing.csv")
        csv_data = self._make_csv_content(
            [
                {
                    "id": "99",
                    "description": "test",
                    "date_published": "2024-01-01",
                    "author": "a",
                    "type": "remote",
                    "platform": "linux",
                    "codes": "CVE-2024-3094",
                },
            ]
        )
        mock_resp = MagicMock()
        mock_resp.read.return_value = csv_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("manus_agent.tools.search_poc_sources._EXPLOITDB_CACHE", cache):
            with patch(
                "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
                return_value=mock_resp,
            ):
                path = _ensure_exploitdb_cache()
                assert path == cache

    def test_uses_cache_when_fresh(self, tmp_path):
        from manus_agent.tools.search_poc_sources import _ensure_exploitdb_cache

        cache = str(tmp_path / "cache.csv")
        with open(cache, "wb") as f:
            f.write(b"id,description\\n1,test\\n")

        with patch("manus_agent.tools.search_poc_sources._EXPLOITDB_CACHE", cache):
            with patch("manus_agent.tools.search_poc_sources.time.time", return_value=time.time()):
                path = _ensure_exploitdb_cache()
        assert path == cache

    def test_returns_empty_when_download_fails(self, tmp_path):
        from manus_agent.tools.search_poc_sources import _fetch_exploitdb

        cache = str(tmp_path / "no.csv")
        with patch("manus_agent.tools.search_poc_sources._EXPLOITDB_CACHE", cache):
            with patch(
                "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
                side_effect=OSError("download failed"),
            ):
                results = _fetch_exploitdb("CVE-2024-3094")
        assert results == []


# ---------------------------------------------------------------------------
# _fetch_github
# ---------------------------------------------------------------------------


class TestFetchGithub:
    def _make_gh_payload(self) -> dict:
        return {
            "items": [
                {
                    "html_url": "https://github.com/user/cve-2024-3094-poc",
                    "full_name": "user/cve-2024-3094-poc",
                    "name": "cve-2024-3094-poc",
                    "pushed_at": "2024-04-15T00:00:00Z",
                    "owner": {"login": "user"},
                }
            ]
        }

    def test_returns_repo_result(self):
        from manus_agent.tools.search_poc_sources import _fetch_github

        with _patch_urlopen(self._make_gh_payload()):
            results = _fetch_github("CVE-2024-3094")

        assert len(results) == 1
        assert results[0]["source"] == "github"
        assert results[0]["url"] == "https://github.com/user/cve-2024-3094-poc"
        assert results[0]["published"] == "2024-04-15"
        assert results[0]["author"] == "user"
        assert results[0]["exploited_in_wild"] is False

    def test_returns_empty_on_error(self):
        from manus_agent.tools.search_poc_sources import _fetch_github

        with patch(
            "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
            side_effect=OSError("timeout"),
        ):
            results = _fetch_github("CVE-2024-3094")
        assert results == []

    def test_returns_empty_when_no_items(self):
        from manus_agent.tools.search_poc_sources import _fetch_github

        with _patch_urlopen({"items": []}):
            results = _fetch_github("CVE-2024-3094")
        assert results == []

    def test_uses_github_token_when_set(self):
        from manus_agent.tools.search_poc_sources import _fetch_github

        req_calls = []

        def capturing_request(url, headers=None):
            req_calls.append(headers or {})
            m = MagicMock()
            return m

        with (
            patch.dict(os.environ, {"GITHUB_TOKEN": "mytoken"}),
            patch("manus_agent.tools.search_poc_sources.urllib.request.Request", side_effect=capturing_request),
            patch(
                "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
                return_value=_make_url_response({"items": []}),
            ),
        ):
            _fetch_github("CVE-2024-3094")

        assert req_calls, "Request was not called"
        assert "Authorization" in req_calls[0]
        assert "mytoken" in req_calls[0]["Authorization"]

    def test_none_pushed_at_yields_none_published(self):
        from manus_agent.tools.search_poc_sources import _fetch_github

        payload = {
            "items": [
                {
                    "html_url": "https://github.com/a/b",
                    "full_name": "a/b",
                    "name": "b",
                    "pushed_at": None,
                    "owner": {"login": "a"},
                }
            ]
        }
        with _patch_urlopen(payload):
            results = _fetch_github("CVE-2024-3094")
        assert results[0]["published"] is None


# ---------------------------------------------------------------------------
# _fetch_nvd
# ---------------------------------------------------------------------------


class TestFetchNvd:
    def _make_nvd_payload(self, ref_url: str) -> dict:
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-3094",
                        "published": "2024-03-29T00:00:00.000",
                        "references": [
                            {"url": ref_url, "tags": ["Exploit"]},
                        ],
                    }
                }
            ]
        }

    def test_returns_github_ref(self):
        from manus_agent.tools.search_poc_sources import _fetch_nvd

        with _patch_urlopen(self._make_nvd_payload("https://github.com/user/poc")):
            results = _fetch_nvd("CVE-2024-3094")
        assert len(results) == 1
        assert results[0]["source"] == "nvd"
        assert results[0]["url"] == "https://github.com/user/poc"

    def test_returns_exploitdb_ref(self):
        from manus_agent.tools.search_poc_sources import _fetch_nvd

        with _patch_urlopen(self._make_nvd_payload("https://www.exploit-db.com/exploits/12345")):
            results = _fetch_nvd("CVE-2024-3094")
        assert len(results) == 1

    def test_returns_packetstorm_ref(self):
        from manus_agent.tools.search_poc_sources import _fetch_nvd

        with _patch_urlopen(self._make_nvd_payload("https://packetstormsecurity.com/files/12345")):
            results = _fetch_nvd("CVE-2024-3094")
        assert len(results) == 1

    def test_ignores_unrelated_refs(self):
        from manus_agent.tools.search_poc_sources import _fetch_nvd

        with _patch_urlopen(self._make_nvd_payload("https://example.com/advisory")):
            results = _fetch_nvd("CVE-2024-3094")
        assert results == []

    def test_returns_empty_on_error(self):
        from manus_agent.tools.search_poc_sources import _fetch_nvd

        with patch(
            "manus_agent.tools.search_poc_sources.urllib.request.urlopen",
            side_effect=OSError("timeout"),
        ):
            results = _fetch_nvd("CVE-2024-3094")
        assert results == []

    def test_returns_empty_when_no_vulnerabilities(self):
        from manus_agent.tools.search_poc_sources import _fetch_nvd

        with _patch_urlopen({"vulnerabilities": []}):
            results = _fetch_nvd("CVE-2024-3094")
        assert results == []

    def test_tags_lowercased(self):
        from manus_agent.tools.search_poc_sources import _fetch_nvd

        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "published": "2024-03-29T00:00:00.000",
                        "references": [
                            {"url": "https://github.com/x/y", "tags": ["Exploit", "Patch"]},
                        ],
                    }
                }
            ]
        }
        with _patch_urlopen(payload):
            results = _fetch_nvd("CVE-2024-3094")
        assert "exploit" in results[0]["tags"]
        assert "patch" in results[0]["tags"]


# ---------------------------------------------------------------------------
# aggregate_poc_results — deduplication, sort, flags
# ---------------------------------------------------------------------------


class TestAggregatePocResults:
    def _run_with_mocked(self, results_by_source: dict, cve_id: str = "CVE-2024-3094"):
        """Run aggregate_poc_results with all individual _fetch_* functions mocked."""
        from manus_agent.tools.search_poc_sources import aggregate_poc_results

        all_src = ["trickest", "vulncheck_kev", "exploitdb", "github", "nvd"]
        patches = [
            patch(
                f"manus_agent.tools.search_poc_sources._fetch_{s}",
                return_value=results_by_source.get(s, []),
            )
            for s in all_src
        ]
        for p in patches:
            p.start()
        try:
            return aggregate_poc_results(cve_id)
        finally:
            for p in patches:
                p.stop()

    def test_deduplication_by_normalized_url(self):
        url = "https://github.com/user/repo"
        r1 = {
            "source": "trickest",
            "url": url,
            "title": "t1",
            "published": None,
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        r2 = {
            "source": "github",
            "url": url + "/",
            "title": "t2",
            "published": None,
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        result = self._run_with_mocked({"trickest": [r1], "github": [r2]})
        assert result["total_found"] == 1

    def test_deduplication_strips_git_suffix(self):
        url1 = "https://github.com/user/repo.git"
        url2 = "https://github.com/user/repo"
        r1 = {
            "source": "nvd",
            "url": url1,
            "title": "t1",
            "published": None,
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        r2 = {
            "source": "github",
            "url": url2,
            "title": "t2",
            "published": None,
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        result = self._run_with_mocked({"nvd": [r1], "github": [r2]})
        assert result["total_found"] == 1

    def test_exploited_in_wild_flag_merged_on_dedup(self):
        url = "https://github.com/user/repo"
        r1 = {
            "source": "github",
            "url": url,
            "title": "t1",
            "published": None,
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        r2 = {
            "source": "vulncheck_kev",
            "url": url,
            "title": "t2",
            "published": None,
            "author": None,
            "tags": ["kev"],
            "exploited_in_wild": True,
        }
        result = self._run_with_mocked({"github": [r1], "vulncheck_kev": [r2]})
        assert result["total_found"] == 1
        assert result["results"][0]["exploited_in_wild"] is True

    def test_sort_kev_first(self):
        r_kev = {
            "source": "vulncheck_kev",
            "url": "https://vulncheck.com/kev/x",
            "title": "kev",
            "published": "2020-01-01",
            "author": None,
            "tags": ["kev"],
            "exploited_in_wild": True,
        }
        r_github = {
            "source": "github",
            "url": "https://github.com/u/r",
            "title": "gh",
            "published": "2024-04-01",
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        result = self._run_with_mocked({"vulncheck_kev": [r_kev], "github": [r_github]})
        assert result["results"][0]["source"] == "vulncheck_kev"
        assert result["exploited_in_wild"] is True

    def test_sort_by_date_descending_after_kev(self):
        r_old = {
            "source": "github",
            "url": "https://github.com/u/old",
            "title": "old",
            "published": "2020-01-01",
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        r_new = {
            "source": "exploitdb",
            "url": "https://exploit-db.com/x",
            "title": "new",
            "published": "2024-01-01",
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        result = self._run_with_mocked({"github": [r_old], "exploitdb": [r_new]})
        dates = [r["published"] for r in result["results"]]
        assert dates[0] >= dates[1]

    def test_none_dates_sorted_last(self):
        r_dated = {
            "source": "github",
            "url": "https://github.com/u/a",
            "title": "a",
            "published": "2024-01-01",
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        r_nodated = {
            "source": "nvd",
            "url": "https://github.com/u/b",
            "title": "b",
            "published": None,
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        result = self._run_with_mocked({"github": [r_dated], "nvd": [r_nodated]})
        last = result["results"][-1]
        assert last["published"] is None

    def test_recent_activity_flag(self):
        from datetime import datetime, timezone

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        r = {
            "source": "github",
            "url": "https://github.com/u/x",
            "title": "x",
            "published": today,
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        result = self._run_with_mocked({"github": [r]})
        assert result["recent_activity"] is True

    def test_no_recent_activity_for_old_dates(self):
        r = {
            "source": "nvd",
            "url": "https://github.com/u/x",
            "title": "x",
            "published": "2020-01-01",
            "author": None,
            "tags": [],
            "exploited_in_wild": False,
        }
        result = self._run_with_mocked({"nvd": [r]})
        assert result["recent_activity"] is False

    def test_sources_filter(self):
        from manus_agent.tools.search_poc_sources import aggregate_poc_results

        with (
            patch("manus_agent.tools.search_poc_sources._fetch_trickest", return_value=[]) as mock_t,
            patch("manus_agent.tools.search_poc_sources._fetch_github", return_value=[]) as mock_g,
            patch("manus_agent.tools.search_poc_sources._fetch_vulncheck_kev", return_value=[]),
            patch("manus_agent.tools.search_poc_sources._fetch_exploitdb", return_value=[]),
            patch("manus_agent.tools.search_poc_sources._fetch_nvd", return_value=[]),
        ):
            aggregate_poc_results("CVE-2024-3094", sources=["trickest", "github"])
            mock_t.assert_called_once()
            mock_g.assert_called_once()

    def test_failed_source_recorded(self):
        from manus_agent.tools.search_poc_sources import aggregate_poc_results

        with (
            patch("manus_agent.tools.search_poc_sources._fetch_trickest", return_value=[]),
            patch("manus_agent.tools.search_poc_sources._fetch_vulncheck_kev", return_value=[]),
            patch("manus_agent.tools.search_poc_sources._fetch_exploitdb", return_value=[]),
            patch("manus_agent.tools.search_poc_sources._fetch_github", side_effect=RuntimeError("boom")),
            patch("manus_agent.tools.search_poc_sources._fetch_nvd", return_value=[]),
        ):
            result = aggregate_poc_results("CVE-2024-3094")

        assert "github" in result["sources_failed"]

    def test_sources_checked_includes_all_queried(self):
        result = self._run_with_mocked({})
        assert set(result["sources_checked"]) == {"trickest", "vulncheck_kev", "exploitdb", "github", "nvd"}

    def test_empty_result_when_all_sources_return_empty(self):
        result = self._run_with_mocked({})
        assert result["total_found"] == 0
        assert result["exploited_in_wild"] is False
        assert result["recent_activity"] is False
        assert result["results"] == []


# ---------------------------------------------------------------------------
# search_poc_sources (Strands tool entry point)
# ---------------------------------------------------------------------------


class TestSearchPocSourcesTool:
    def test_invalid_cve_returns_error(self):
        from manus_agent.tools.search_poc_sources import search_poc_sources

        result = search_poc_sources(cve_id="NOT-A-CVE")
        assert "error" in result
        assert result["total_found"] == 0

    def test_valid_cve_calls_aggregate(self):
        from manus_agent.tools.search_poc_sources import search_poc_sources

        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value={
                "cve_id": "CVE-2024-3094",
                "total_found": 0,
                "exploited_in_wild": False,
                "recent_activity": False,
                "sources_checked": [],
                "sources_failed": [],
                "results": [],
            },
        ) as mock_agg:
            search_poc_sources(cve_id="CVE-2024-3094")
            mock_agg.assert_called_once_with("CVE-2024-3094", None)

    def test_sources_filter_passed_through(self):
        from manus_agent.tools.search_poc_sources import search_poc_sources

        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value={
                "cve_id": "CVE-2024-3094",
                "total_found": 0,
                "exploited_in_wild": False,
                "recent_activity": False,
                "sources_checked": [],
                "sources_failed": [],
                "results": [],
            },
        ) as mock_agg:
            search_poc_sources(cve_id="CVE-2024-3094", sources="trickest,github")
            mock_agg.assert_called_once_with("CVE-2024-3094", ["trickest", "github"])

    def test_empty_sources_string_passes_none(self):
        from manus_agent.tools.search_poc_sources import search_poc_sources

        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value={
                "cve_id": "CVE-2024-3094",
                "total_found": 0,
                "exploited_in_wild": False,
                "recent_activity": False,
                "sources_checked": [],
                "sources_failed": [],
                "results": [],
            },
        ) as mock_agg:
            search_poc_sources(cve_id="CVE-2024-3094", sources="")
            mock_agg.assert_called_once_with("CVE-2024-3094", None)

    def test_cve_id_stripped(self):
        from manus_agent.tools.search_poc_sources import search_poc_sources

        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value={
                "cve_id": "CVE-2024-3094",
                "total_found": 0,
                "exploited_in_wild": False,
                "recent_activity": False,
                "sources_checked": [],
                "sources_failed": [],
                "results": [],
            },
        ) as mock_agg:
            search_poc_sources(cve_id="  CVE-2024-3094  ")
            call_args = mock_agg.call_args[0][0]
            assert call_args == "CVE-2024-3094"


# ---------------------------------------------------------------------------
# CLI — _run_poc_search
# ---------------------------------------------------------------------------


class TestCliPocSearch:
    def _make_result(self, exploited=False, recent=False, results=None):
        return {
            "cve_id": "CVE-2024-3094",
            "total_found": len(results or []),
            "exploited_in_wild": exploited,
            "recent_activity": recent,
            "sources_checked": ["trickest", "nvd"],
            "sources_failed": [],
            "results": results or [],
        }

    def test_json_output(self, capsys):
        from manus_agent.cli import _run_poc_search

        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=self._make_result(),
        ):
            rc = _run_poc_search(["CVE-2024-3094", "--output", "json"])

        assert rc == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["cve_id"] == "CVE-2024-3094"

    def test_text_output_with_results(self, capsys):
        from manus_agent.cli import _run_poc_search

        results = [
            {
                "source": "github",
                "url": "https://github.com/user/poc",
                "title": "PoC Repo",
                "published": "2024-04-01",
                "author": "user",
                "tags": ["github-repo"],
                "exploited_in_wild": False,
            }
        ]
        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=self._make_result(results=results),
        ):
            rc = _run_poc_search(["CVE-2024-3094"])

        assert rc == 0
        captured = capsys.readouterr()
        assert "CVE-2024-3094" in captured.out
        assert "github" in captured.out

    def test_text_output_shows_kev_banner(self, capsys):
        from manus_agent.cli import _run_poc_search

        results = [
            {
                "source": "vulncheck_kev",
                "url": "https://vulncheck.com/kev/x",
                "title": "KEV entry",
                "published": "2024-01-01",
                "author": None,
                "tags": ["kev"],
                "exploited_in_wild": True,
            }
        ]
        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=self._make_result(exploited=True, results=results),
        ):
            rc = _run_poc_search(["CVE-2024-3094"])

        assert rc == 0
        captured = capsys.readouterr()
        assert "EXPLOITED IN WILD" in captured.out

    def test_invalid_cve_exits_with_error(self):
        from manus_agent.cli import _run_poc_search

        with pytest.raises(SystemExit):
            _run_poc_search(["NOT-A-CVE"])

    def test_sources_filter_cli_arg(self):
        from manus_agent.cli import _run_poc_search

        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=self._make_result(),
        ) as mock_agg:
            _run_poc_search(["CVE-2024-3094", "--sources", "trickest,github"])
            call_args = mock_agg.call_args
            assert call_args[0][1] == ["trickest", "github"]

    def test_empty_results_text_output(self, capsys):
        from manus_agent.cli import _run_poc_search

        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=self._make_result(),
        ):
            rc = _run_poc_search(["CVE-2024-3094"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "No PoC results found" in out

    def test_recent_activity_shown(self, capsys):
        from manus_agent.cli import _run_poc_search

        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=self._make_result(recent=True),
        ):
            _run_poc_search(["CVE-2024-3094"])
        out = capsys.readouterr().out
        assert "Recent activity" in out

    def test_failed_sources_shown(self, capsys):
        from manus_agent.cli import _run_poc_search

        result = self._make_result()
        result["sources_failed"] = ["exploitdb"]
        with patch(
            "manus_agent.tools.search_poc_sources.aggregate_poc_results",
            return_value=result,
        ):
            _run_poc_search(["CVE-2024-3094"])
        out = capsys.readouterr().out
        assert "exploitdb" in out


# ---------------------------------------------------------------------------
# CLI main() dispatch
# ---------------------------------------------------------------------------


class TestCliMainDispatch:
    def test_poc_search_in_subcommands(self):
        from manus_agent.cli import _SUBCOMMANDS

        assert "poc-search" in _SUBCOMMANDS

    def test_main_dispatches_poc_search(self):
        from manus_agent.cli import main

        with patch("manus_agent.cli._run_poc_search", return_value=0) as mock_run:
            with patch("sys.argv", ["manus-agent", "poc-search", "CVE-2024-3094"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 0
            mock_run.assert_called_once_with(["CVE-2024-3094"])


# ---------------------------------------------------------------------------
# VI agent wiring
# ---------------------------------------------------------------------------


class TestViAgentWiring:
    def test_search_poc_sources_in_vi_agent_tools(self):
        """search_poc_sources should appear in the VI agent tool list."""
        import inspect

        import manus_agent.agents.vi_agent as vi

        src = inspect.getsource(vi)
        assert "search_poc_sources" in src

    def test_search_poc_sources_in_system_prompt(self):
        """System prompt should mention search_poc_sources."""
        import manus_agent.agents.vi_agent as vi

        assert "search_poc_sources" in vi.SYSTEM_PROMPT

    def test_exploited_in_wild_guidance_in_system_prompt(self):
        """System prompt should include exploited_in_wild guidance."""
        import manus_agent.agents.vi_agent as vi

        assert "exploited_in_wild" in vi.SYSTEM_PROMPT
