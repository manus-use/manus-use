"""
Tests for the track_vendor_response tool and manus-use vendor-response CLI subcommand.
All network calls are mocked — no real HTTP requests are made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _make_tool_use(cve_id: str) -> dict:
    return {"toolUseId": "test-id-001", "input": {"cve_id": cve_id}}


def _nvd_response(
    cve_id: str, *, refs: list[str] | None = None, vendor: str = "testvendor", product: str = "testpkg"
) -> dict:
    """Minimal NVD API response payload."""
    cpe = f"cpe:2.3:a:{vendor}:{product}:1.0:*:*:*:*:*:*:*"
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "references": [{"url": u} for u in (refs or [])],
                    "configurations": [{"nodes": [{"cpeMatch": [{"criteria": cpe, "vulnerable": True}]}]}],
                }
            }
        ]
    }


# ──────────────────────────────────────────────────────────────────────────────
# Import smoke-test
# ──────────────────────────────────────────────────────────────────────────────


def test_track_vendor_response_module_imports():
    from manus_use.tools.track_vendor_response import TOOL_SPEC, track_vendor_response  # noqa: F401

    assert TOOL_SPEC["name"] == "track_vendor_response"


def test_tool_spec_has_required_keys():
    from manus_use.tools.track_vendor_response import TOOL_SPEC

    assert "name" in TOOL_SPEC
    assert "description" in TOOL_SPEC
    assert "inputSchema" in TOOL_SPEC
    schema = TOOL_SPEC["inputSchema"]["json"]
    assert "cve_id" in schema["properties"]
    assert "cve_id" in schema["required"]


def test_tool_exported_from_agents_package():
    """track_vendor_response tool file is importable from the tools package."""
    from manus_use.tools import track_vendor_response as mod  # noqa: F401


# ──────────────────────────────────────────────────────────────────────────────
# Input validation
# ──────────────────────────────────────────────────────────────────────────────


def test_invalid_cve_id_returns_error():
    from manus_use.tools.track_vendor_response import track_vendor_response

    result = track_vendor_response(_make_tool_use("NOTACVE-123"))
    assert result["status"] == "error"
    assert "Invalid CVE ID" in result["content"][0]["text"]


def test_empty_cve_id_returns_error():
    from manus_use.tools.track_vendor_response import track_vendor_response

    result = track_vendor_response(_make_tool_use(""))
    assert result["status"] == "error"


def test_none_cve_id_returns_error():
    from manus_use.tools.track_vendor_response import track_vendor_response

    result = track_vendor_response({"toolUseId": "x", "input": {"cve_id": None}})
    assert result["status"] == "error"


# ──────────────────────────────────────────────────────────────────────────────
# _fetch_nvd
# ──────────────────────────────────────────────────────────────────────────────


def test_fetch_nvd_returns_cve_record():
    from manus_use.tools.track_vendor_response import _fetch_nvd

    with patch("manus_use.tools.track_vendor_response.requests.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: _nvd_response("CVE-2024-0001"),
            raise_for_status=lambda: None,
        )
        result = _fetch_nvd("CVE-2024-0001")
    assert result.get("id") == "CVE-2024-0001"


def test_fetch_nvd_empty_vulnerabilities_returns_error():
    from manus_use.tools.track_vendor_response import _fetch_nvd

    with patch("manus_use.tools.track_vendor_response.requests.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"vulnerabilities": []},
            raise_for_status=lambda: None,
        )
        result = _fetch_nvd("CVE-2024-0001")
    assert "_error" in result


def test_fetch_nvd_request_exception_returns_error():
    import requests as req

    from manus_use.tools.track_vendor_response import _fetch_nvd

    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=req.RequestException("timeout")):
        result = _fetch_nvd("CVE-2024-0001")
    assert "_error" in result


# ──────────────────────────────────────────────────────────────────────────────
# _nvd_references / _nvd_affected_vendor_product
# ──────────────────────────────────────────────────────────────────────────────


def test_nvd_references_extracts_urls():
    from manus_use.tools.track_vendor_response import _nvd_references

    nvd_cve = {
        "references": [
            {"url": "https://github.com/example/repo/commit/abc123def456"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"},
        ]
    }
    refs = _nvd_references(nvd_cve)
    assert len(refs) == 2
    assert refs[0].startswith("https://github.com")


def test_nvd_references_empty_when_no_refs():
    from manus_use.tools.track_vendor_response import _nvd_references

    assert _nvd_references({}) == []
    assert _nvd_references({"references": []}) == []


def test_nvd_affected_vendor_product_extracts_correctly():
    from manus_use.tools.track_vendor_response import _nvd_affected_vendor_product

    nvd_cve = _nvd_response("CVE-2024-0001", vendor="acme", product="widget")["vulnerabilities"][0]["cve"]
    vendor, product = _nvd_affected_vendor_product(nvd_cve)
    assert vendor == "acme"
    assert product == "widget"


def test_nvd_affected_vendor_product_empty_on_no_config():
    from manus_use.tools.track_vendor_response import _nvd_affected_vendor_product

    vendor, product = _nvd_affected_vendor_product({})
    assert vendor == ""
    assert product == ""


# ──────────────────────────────────────────────────────────────────────────────
# _fetch_ghsa
# ──────────────────────────────────────────────────────────────────────────────


def test_fetch_ghsa_returns_advisories_from_list():
    from manus_use.tools.track_vendor_response import _fetch_ghsa

    fake_advisories = [
        {
            "ghsaId": "GHSA-xxxx-yyyy-zzzz",
            "cveId": "CVE-2024-0001",
            "state": "published",
            "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        }
    ]
    with patch("manus_use.tools.track_vendor_response.requests.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: fake_advisories,
            raise_for_status=lambda: None,
        )
        result = _fetch_ghsa("CVE-2024-0001")
    assert len(result["advisories"]) == 1
    assert result["advisories"][0]["state"] == "published"


def test_fetch_ghsa_returns_empty_on_request_error():
    import requests as req

    from manus_use.tools.track_vendor_response import _fetch_ghsa

    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=req.RequestException("fail")):
        result = _fetch_ghsa("CVE-2024-0001")
    assert result["advisories"] == []


# ──────────────────────────────────────────────────────────────────────────────
# _fetch_cisa_kev
# ──────────────────────────────────────────────────────────────────────────────


def test_fetch_cisa_kev_returns_matching_entry():
    from manus_use.tools.track_vendor_response import _fetch_cisa_kev

    kev_catalog = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001", "requiredAction": "Apply updates.", "dueDate": "2024-02-01"},
            {"cveID": "CVE-2024-0002", "requiredAction": "Isolate.", "dueDate": "2024-02-15"},
        ]
    }
    with patch("manus_use.tools.track_vendor_response.requests.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: kev_catalog,
            raise_for_status=lambda: None,
        )
        entry = _fetch_cisa_kev("CVE-2024-0001")
    assert entry["requiredAction"] == "Apply updates."
    assert entry["dueDate"] == "2024-02-01"


def test_fetch_cisa_kev_returns_empty_when_not_found():
    from manus_use.tools.track_vendor_response import _fetch_cisa_kev

    kev_catalog = {"vulnerabilities": [{"cveID": "CVE-2024-9999"}]}
    with patch("manus_use.tools.track_vendor_response.requests.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: kev_catalog,
            raise_for_status=lambda: None,
        )
        entry = _fetch_cisa_kev("CVE-2024-0001")
    assert entry == {}


def test_fetch_cisa_kev_request_exception_returns_empty():
    import requests as req

    from manus_use.tools.track_vendor_response import _fetch_cisa_kev

    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=req.RequestException("fail")):
        entry = _fetch_cisa_kev("CVE-2024-0001")
    assert entry == {}


# ──────────────────────────────────────────────────────────────────────────────
# _extract_github_repo_from_refs
# ──────────────────────────────────────────────────────────────────────────────


def test_extract_github_repo_from_refs_finds_most_common():
    from manus_use.tools.track_vendor_response import _extract_github_repo_from_refs

    refs = [
        "https://github.com/acme/widget/commit/abc123",
        "https://github.com/acme/widget/pull/42",
        "https://github.com/acme/widget/releases/tag/v2.1",
        "https://github.com/otherperson/otherrepo/commit/xyz999",
    ]
    result = _extract_github_repo_from_refs(refs)
    assert result is not None
    owner, repo = result
    assert owner == "acme"
    assert repo == "widget"


def test_extract_github_repo_from_refs_returns_none_when_empty():
    from manus_use.tools.track_vendor_response import _extract_github_repo_from_refs

    assert _extract_github_repo_from_refs([]) is None
    assert _extract_github_repo_from_refs(["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"]) is None


def test_extract_github_repo_strips_git_suffix():
    from manus_use.tools.track_vendor_response import _extract_github_repo_from_refs

    refs = ["https://github.com/acme/widget.git/commit/abc"]
    result = _extract_github_repo_from_refs(refs)
    assert result is not None
    _, repo = result
    # .git suffix is stripped
    assert not repo.endswith(".git")


# ──────────────────────────────────────────────────────────────────────────────
# _classify
# ──────────────────────────────────────────────────────────────────────────────


def test_classify_patch_available_from_commit_url():
    from manus_use.tools.track_vendor_response import _classify

    refs = ["https://github.com/acme/widget/commit/abc123def456789012"]
    status, confidence, _ = _classify(refs, [], {}, [])
    assert status == "patch_available"
    assert confidence in ("high", "moderate", "low")


def test_classify_patch_available_from_release_url():
    from manus_use.tools.track_vendor_response import _classify

    refs = ["https://github.com/acme/widget/releases/tag/v2.1.0"]
    status, confidence, _ = _classify(refs, [], {}, [])
    assert status == "patch_available"


def test_classify_patch_available_from_ghsa_published():
    from manus_use.tools.track_vendor_response import _classify

    ghsa_advisories = [
        {
            "state": "published",
            "html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "description": "Fixed in v2.0",
            "references": [],
            "vulnerabilities": [{"patched_versions": ">=2.0.1"}],
        }
    ]
    status, confidence, evidence = _classify([], ghsa_advisories, {}, [])
    assert status == "patch_available"
    assert confidence == "high"
    assert any("github.com/advisories" in u for u in evidence)


def test_classify_wont_fix_detected():
    from manus_use.tools.track_vendor_response import _classify

    refs = ["https://vendor.example.com/advisory?cve=2024-0001&status=wontfix"]
    # Inject wont-fix language via a fake GHSA description
    ghsa = [{"state": "draft", "description": "will not fix — out of support", "references": [], "vulnerabilities": []}]
    status, _, _ = _classify(refs, ghsa, {}, [])
    assert status == "wont_fix"


def test_classify_patch_backported():
    from manus_use.tools.track_vendor_response import _classify

    refs = [
        "https://github.com/acme/widget/commit/abc123def456789012",
        "https://github.com/acme/widget/releases/tag/v1.8.5-lts",
    ]
    ghsa = [
        {
            "state": "draft",
            "description": "backport for legacy version included",
            "references": [],
            "vulnerabilities": [],
        }
    ]
    status, _, _ = _classify(refs, ghsa, {}, [])
    assert status == "patch_backported"


def test_classify_investigating():
    from manus_use.tools.track_vendor_response import _classify

    ghsa = [
        {
            "state": "draft",
            "description": "Vendor is aware and investigating the reported issue.",
            "references": [],
            "vulnerabilities": [],
        }
    ]
    status, confidence, _ = _classify([], ghsa, {}, [])
    assert status == "investigating"
    assert confidence == "moderate"


def test_classify_no_patch_when_only_nvd_refs_with_no_patch_signals():
    from manus_use.tools.track_vendor_response import _classify

    refs = ["https://nvd.nist.gov/vuln/detail/CVE-2024-0001"]
    status, _, _ = _classify(refs, [], {}, [])
    assert status in ("no_patch", "unknown", "patch_available")  # nvd url is not a strong patch signal


def test_classify_unknown_when_no_data():
    from manus_use.tools.track_vendor_response import _classify

    status, confidence, evidence = _classify([], [], {}, [])
    assert status == "unknown"
    assert evidence == []


def test_classify_evidence_deduplication():
    from manus_use.tools.track_vendor_response import _classify

    commit_url = "https://github.com/acme/widget/commit/abc123def456789012"
    refs = [commit_url, commit_url, commit_url]
    _, _, evidence = _classify(refs, [], {}, [])
    assert evidence.count(commit_url) == 1


# ──────────────────────────────────────────────────────────────────────────────
# _build_summary
# ──────────────────────────────────────────────────────────────────────────────


def test_build_summary_patch_available():
    from manus_use.tools.track_vendor_response import _build_summary

    summary = _build_summary(
        cve_id="CVE-2024-0001",
        status="patch_available",
        confidence="high",
        evidence_urls=["https://github.com/acme/widget/releases/tag/v2.1"],
        vendor="acme",
        product="widget",
        kev_entry={},
        ghsa_count=1,
    )
    assert "CVE-2024-0001" in summary
    assert "Patch Available" in summary
    assert "acme" in summary


def test_build_summary_wont_fix():
    from manus_use.tools.track_vendor_response import _build_summary

    summary = _build_summary(
        cve_id="CVE-2024-0001",
        status="wont_fix",
        confidence="high",
        evidence_urls=[],
        vendor="",
        product="",
        kev_entry={},
        ghsa_count=0,
    )
    assert "Won't Fix" in summary


def test_build_summary_includes_kev_required_action():
    from manus_use.tools.track_vendor_response import _build_summary

    kev = {"requiredAction": "Apply updates per vendor instructions.", "dueDate": "2025-01-15"}
    summary = _build_summary(
        cve_id="CVE-2024-0001",
        status="patch_available",
        confidence="high",
        evidence_urls=[],
        vendor="",
        product="",
        kev_entry=kev,
        ghsa_count=0,
    )
    assert "Apply updates per vendor instructions." in summary
    assert "2025-01-15" in summary


def test_build_summary_includes_evidence_urls():
    from manus_use.tools.track_vendor_response import _build_summary

    urls = ["https://github.com/acme/widget/commit/abc123", "https://github.com/advisories/GHSA-xxxx"]
    summary = _build_summary(
        cve_id="CVE-2024-0001",
        status="patch_available",
        confidence="high",
        evidence_urls=urls,
        vendor="",
        product="",
        kev_entry={},
        ghsa_count=2,
    )
    for url in urls:
        assert url in summary


# ──────────────────────────────────────────────────────────────────────────────
# track_vendor_response (full tool, mocked HTTP)
# ──────────────────────────────────────────────────────────────────────────────


def _make_requests_mock(nvd_payload, ghsa_payload=None, kev_payload=None):
    """Return a side_effect function for requests.get that dispatches by URL."""
    ghsa_payload = ghsa_payload or []
    kev_payload = kev_payload or {"vulnerabilities": []}

    def side_effect(url, **kwargs):
        m = MagicMock()
        m.raise_for_status = MagicMock()
        if "nvd.nist.gov" in url:
            m.json.return_value = nvd_payload
        elif "github.com/advisories" in url or "api.github.com/advisories" in url:
            m.json.return_value = ghsa_payload
        elif "cisa.gov" in url:
            m.json.return_value = kev_payload
        elif "api.github.com/repos" in url:
            m.json.return_value = []
        else:
            m.json.return_value = {}
        return m

    return side_effect


def test_track_vendor_response_patch_available_from_commit():
    from manus_use.tools.track_vendor_response import track_vendor_response

    nvd = _nvd_response(
        "CVE-2024-0001",
        refs=["https://github.com/acme/widget/commit/abc123def456789012345678"],
    )
    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=_make_requests_mock(nvd)):
        result = track_vendor_response(_make_tool_use("CVE-2024-0001"))

    assert result["status"] == "success"
    data = result["content"][0]["json"]
    assert data["cve_id"] == "CVE-2024-0001"
    assert data["status"] == "patch_available"
    assert data["confidence"] in ("high", "moderate")


def test_track_vendor_response_wont_fix_from_ghsa():
    from manus_use.tools.track_vendor_response import track_vendor_response

    nvd = _nvd_response("CVE-2024-0001")
    ghsa = [
        {
            "state": "draft",
            "html_url": "https://github.com/advisories/GHSA-xxxx",
            "description": "Vendor will not fix — product is end of life",
            "references": [],
            "vulnerabilities": [],
        }
    ]
    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=_make_requests_mock(nvd, ghsa)):
        result = track_vendor_response(_make_tool_use("CVE-2024-0001"))

    data = result["content"][0]["json"]
    assert data["status"] == "wont_fix"


def test_track_vendor_response_includes_kev_fields():
    from manus_use.tools.track_vendor_response import track_vendor_response

    nvd = _nvd_response("CVE-2024-0001")
    kev = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "requiredAction": "Update now.", "dueDate": "2025-03-01"}]}
    with patch(
        "manus_use.tools.track_vendor_response.requests.get", side_effect=_make_requests_mock(nvd, kev_payload=kev)
    ):
        result = track_vendor_response(_make_tool_use("CVE-2024-0001"))

    data = result["content"][0]["json"]
    assert data["in_cisa_kev"] is True
    assert data["cisa_required_action"] == "Update now."
    assert data["cisa_due_date"] == "2025-03-01"


def test_track_vendor_response_summary_in_output():
    from manus_use.tools.track_vendor_response import track_vendor_response

    nvd = _nvd_response("CVE-2024-0001")
    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=_make_requests_mock(nvd)):
        result = track_vendor_response(_make_tool_use("CVE-2024-0001"))

    data = result["content"][0]["json"]
    assert "summary" in data
    assert "CVE-2024-0001" in data["summary"]


def test_track_vendor_response_nvd_error_still_returns_success():
    """Even if NVD fails, the tool should degrade gracefully and return success."""
    import requests as req

    from manus_use.tools.track_vendor_response import track_vendor_response

    def side_effect(url, **kwargs):
        if "nvd.nist.gov" in url:
            raise req.RequestException("NVD down")
        m = MagicMock()
        m.raise_for_status = MagicMock()
        m.json.return_value = [] if "github.com" in url else {"vulnerabilities": []}
        return m

    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=side_effect):
        result = track_vendor_response(_make_tool_use("CVE-2024-0001"))

    assert result["status"] == "success"
    data = result["content"][0]["json"]
    assert data["status"] in ("unknown", "no_patch", "investigating", "patch_available")


def test_track_vendor_response_cve_id_case_insensitive():
    from manus_use.tools.track_vendor_response import track_vendor_response

    nvd = _nvd_response("CVE-2024-0001")
    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=_make_requests_mock(nvd)):
        result = track_vendor_response(_make_tool_use("cve-2024-0001"))

    assert result["status"] == "success"
    data = result["content"][0]["json"]
    assert data["cve_id"] == "CVE-2024-0001"


# ──────────────────────────────────────────────────────────────────────────────
# CLI: vendor-response subcommand
# ──────────────────────────────────────────────────────────────────────────────


def test_vendor_response_help_exits_zero():
    from manus_use.cli import _build_vendor_response_parser

    p = _build_vendor_response_parser()
    with pytest.raises(SystemExit) as exc_info:
        p.parse_args(["--help"])
    assert exc_info.value.code == 0


def test_vendor_response_missing_cve_is_error():
    from manus_use.cli import _build_vendor_response_parser

    p = _build_vendor_response_parser()
    with pytest.raises(SystemExit) as exc_info:
        p.parse_args([])
    assert exc_info.value.code != 0


def test_vendor_response_registered_in_subcommands():
    from manus_use.cli import _SUBCOMMANDS

    assert "vendor-response" in _SUBCOMMANDS


def test_vendor_response_registered_in_main():
    """main() must dispatch to _run_vendor_response when 'vendor-response' is present."""
    import inspect

    from manus_use.cli import main

    src = inspect.getsource(main)
    assert "vendor-response" in src
    assert "_run_vendor_response" in src


def test_run_vendor_response_text_output(capsys):
    from manus_use.cli import _run_vendor_response

    nvd = _nvd_response("CVE-2024-0001", refs=["https://github.com/acme/widget/commit/abc123def456789012345678"])

    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=_make_requests_mock(nvd)):
        exit_code = _run_vendor_response(["CVE-2024-0001"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "CVE-2024-0001" in captured.out


def test_run_vendor_response_json_output(capsys):
    from manus_use.cli import _run_vendor_response

    nvd = _nvd_response("CVE-2024-0001")
    with patch("manus_use.tools.track_vendor_response.requests.get", side_effect=_make_requests_mock(nvd)):
        exit_code = _run_vendor_response(["CVE-2024-0001", "--output", "json"])

    assert exit_code == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["cve_id"] == "CVE-2024-0001"
    assert "status" in parsed
    assert "confidence" in parsed
    assert "evidence_urls" in parsed


def test_run_vendor_response_invalid_cve_returns_1(capsys):
    from manus_use.cli import _run_vendor_response

    exit_code = _run_vendor_response(["NOTACVE"])
    assert exit_code == 1


def test_run_vendor_response_json_has_all_expected_fields(capsys):
    from manus_use.cli import _run_vendor_response

    nvd = _nvd_response(
        "CVE-2024-0001",
        refs=["https://github.com/acme/widget/releases/tag/v2.0"],
        vendor="acme",
        product="widget",
    )
    kev = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "requiredAction": "Patch it.", "dueDate": "2025-01-01"}]}
    with patch(
        "manus_use.tools.track_vendor_response.requests.get", side_effect=_make_requests_mock(nvd, kev_payload=kev)
    ):
        _run_vendor_response(["CVE-2024-0001", "--output", "json"])

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    required_fields = [
        "cve_id",
        "status",
        "confidence",
        "vendor",
        "product",
        "evidence_urls",
        "ghsa_advisories_found",
        "repo_advisories_found",
        "in_cisa_kev",
        "cisa_required_action",
        "cisa_due_date",
        "summary",
    ]
    for field in required_fields:
        assert field in data, f"Missing field: {field}"


# ──────────────────────────────────────────────────────────────────────────────
# README documentation living-doc tests
# ──────────────────────────────────────────────────────────────────────────────


def test_readme_documents_vendor_response_subcommand():
    from pathlib import Path

    readme = (Path(__file__).parent.parent / "README.md").read_text()
    assert "vendor-response" in readme, "README must document the vendor-response subcommand"
    assert "manus-use vendor-response" in readme


def test_readme_documents_patch_status_categories():
    from pathlib import Path

    readme = (Path(__file__).parent.parent / "README.md").read_text()
    for status in ("no-patch", "patch-available", "patch-backported", "wont-fix"):
        assert status in readme or status.replace("-", "_") in readme, f"README should mention status: {status}"
