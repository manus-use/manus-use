"""Tests for get_trickest_pocs tool."""

from __future__ import annotations

import urllib.error
from unittest.mock import MagicMock, patch

from manus_use.tools.get_trickest_pocs import _parse_pocs, get_trickest_pocs

# --- Unit tests for _parse_pocs ---

SAMPLE_MARKDOWN = """### [CVE-2025-6554](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-6554)

### Description

Type confusion in V8 in Google Chrome prior to 138.0.7204.96.

### POC

#### Reference
- https://chromereleases.googleblog.com/2025/06/example

#### Github
- https://github.com/example/CVE-2025-6554
- https://github.com/another/exploit-poc
"""

NO_POC_MARKDOWN = """### [CVE-2024-0001](https://cve.mitre.org)

### Description

Some vulnerability with no public PoCs.

### POC

#### Reference
No PoCs from references.

#### Github
No PoCs from Github.
"""


def test_parse_pocs_extracts_description():
    data = _parse_pocs(SAMPLE_MARKDOWN)
    assert "Type confusion" in data["description"]


def test_parse_pocs_extracts_reference_pocs():
    data = _parse_pocs(SAMPLE_MARKDOWN)
    assert len(data["reference_pocs"]) == 1
    assert "chromereleases" in data["reference_pocs"][0]


def test_parse_pocs_extracts_github_pocs():
    data = _parse_pocs(SAMPLE_MARKDOWN)
    assert len(data["github_pocs"]) == 2
    assert any("CVE-2025-6554" in u for u in data["github_pocs"])


def test_parse_pocs_all_pocs_deduped():
    data = _parse_pocs(SAMPLE_MARKDOWN)
    assert len(data["all_pocs"]) == len(set(data["all_pocs"]))
    assert len(data["all_pocs"]) == 3


def test_parse_pocs_no_pocs():
    data = _parse_pocs(NO_POC_MARKDOWN)
    assert data["all_pocs"] == []
    assert data["reference_pocs"] == []
    assert data["github_pocs"] == []


# --- Integration-style tests for get_trickest_pocs (mocked HTTP) ---


def _make_mock_response(content: str):
    mock_resp = MagicMock()
    mock_resp.read.return_value = content.encode("utf-8")
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def test_invalid_cve_format():
    result = get_trickest_pocs("NOT-A-CVE")
    assert "Invalid CVE ID format" in result


def test_valid_cve_returns_pocs():
    with patch("urllib.request.urlopen", return_value=_make_mock_response(SAMPLE_MARKDOWN)):
        result = get_trickest_pocs("CVE-2025-6554")
    assert "trickest/cve PoC Report" in result
    assert "CVE-2025-6554" in result
    assert "github.com/example" in result


def test_valid_cve_case_insensitive():
    with patch("urllib.request.urlopen", return_value=_make_mock_response(SAMPLE_MARKDOWN)):
        result = get_trickest_pocs("cve-2025-6554")
    assert "CVE-2025-6554" in result


def test_404_returns_not_found_message():
    http_error = urllib.error.HTTPError(url="", code=404, msg="Not Found", hdrs=None, fp=None)
    with patch("urllib.request.urlopen", side_effect=http_error):
        result = get_trickest_pocs("CVE-2099-9999")
    assert "No trickest/cve entry found" in result


def test_http_error_non_404():
    http_error = urllib.error.HTTPError(url="", code=500, msg="Server Error", hdrs=None, fp=None)
    with patch("urllib.request.urlopen", side_effect=http_error):
        result = get_trickest_pocs("CVE-2025-1234")
    assert "HTTP error" in result
    assert "500" in result


def test_no_pocs_found_message():
    with patch("urllib.request.urlopen", return_value=_make_mock_response(NO_POC_MARKDOWN)):
        result = get_trickest_pocs("CVE-2024-0001")
    assert "no PoC links listed" in result


def test_url_constructed_with_correct_year():
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _make_mock_response(SAMPLE_MARKDOWN)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        get_trickest_pocs("CVE-2023-44487")

    assert "2023" in captured["url"]
    assert "CVE-2023-44487" in captured["url"]
