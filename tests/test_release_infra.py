"""Living-doc tests for the release infrastructure.

These tests guard two files:
  - .github/workflows/publish.yml  — PyPI publish workflow
  - .pre-commit-config.yaml        — pre-commit hooks configuration

The tests verify structural properties (file exists, keys present, triggers
correct) without requiring network access or external tool execution.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISH_YML = ROOT / ".github" / "workflows" / "publish.yml"
PRE_COMMIT_CFG = ROOT / ".pre-commit-config.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict:
    """Parse YAML from *path* and return the top-level dict."""
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        pytest.skip("pyyaml not installed; skipping YAML-parse checks")
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ===========================================================================
# TestPublishWorkflow
# ===========================================================================


class TestPublishWorkflow:
    """Guards .github/workflows/publish.yml."""

    def test_file_exists(self):
        assert PUBLISH_YML.exists(), (
            f"{PUBLISH_YML} not found — create .github/workflows/publish.yml to enable automated PyPI releases"
        )

    def test_parses_as_valid_yaml(self):
        data = _load_yaml(PUBLISH_YML)
        assert isinstance(data, dict), "publish.yml must be a YAML mapping"

    def test_triggers_on_version_tags(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        # Must mention tag-based push trigger
        assert "tags:" in content, "publish.yml must have a tags: trigger so it fires on version tags"
        # Must match semver-style tags (v0.1.0 etc.)
        assert re.search(r"v\[0-9\]", content), "publish.yml tags pattern must match semver tags like v0.1.0"

    def test_has_validate_job(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "validate" in content, "publish.yml must have a validate job that runs tests before publishing"

    def test_has_build_job(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "build" in content, "publish.yml must have a build job that produces sdist + wheel"

    def test_has_publish_pypi_job(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "publish" in content.lower(), "publish.yml must have a job that uploads to PyPI"

    def test_uses_trusted_publishing(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "pypa/gh-action-pypi-publish" in content, (
            "publish.yml must use pypa/gh-action-pypi-publish for OIDC Trusted Publishing "
            "(no long-lived API tokens required)"
        )

    def test_has_github_release_job(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "github-release" in content or "softprops/action-gh-release" in content, (
            "publish.yml should create a GitHub Release with release notes and build artifacts"
        )

    def test_requires_id_token_write_permission(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "id-token: write" in content, (
            "publish.yml must grant id-token: write permission for OIDC Trusted Publishing"
        )

    def test_requires_contents_write_permission(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "contents: write" in content, (
            "publish.yml must grant contents: write permission to create GitHub Releases"
        )

    def test_uses_official_checkout_action(self):
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "actions/checkout@v4" in content, "publish.yml should use actions/checkout@v4 (pinned major version)"

    def test_validates_before_publish(self):
        """Build job must depend on validate completing first."""
        content = PUBLISH_YML.read_text(encoding="utf-8")
        # needs: validate must appear in the build job section
        assert re.search(r"needs:.*validate", content), (
            "The build job must declare 'needs: validate' so tests always run before publishing"
        )

    def test_publish_depends_on_build(self):
        """Publish job must depend on build job."""
        content = PUBLISH_YML.read_text(encoding="utf-8")
        # needs: build must appear in the publish section
        assert re.search(r"needs:.*build", content), (
            "The publish job must declare 'needs: build' so artifacts are ready before upload"
        )

    def test_prerelease_detection_for_tagged_prereleases(self):
        """Pre-release tags (e.g. v0.1.0-rc1) should be marked as GitHub pre-release."""
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "prerelease:" in content, (
            "publish.yml should detect pre-release tags (v0.1.0-rc1) and mark the GitHub Release as a pre-release"
        )

    def test_no_long_lived_api_token(self):
        """Ensure we rely on Trusted Publishing, not a hardcoded PYPI_API_TOKEN."""
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "PYPI_API_TOKEN" not in content and "PYPI_TOKEN" not in content, (
            "publish.yml must not reference PYPI_API_TOKEN — use OIDC Trusted Publishing instead"
        )

    def test_concurrency_cancel_in_progress_false(self):
        """An in-flight publish must never be cancelled."""
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "cancel-in-progress: false" in content, (
            "publish.yml concurrency group must set cancel-in-progress: false "
            "— cancelling an in-flight PyPI upload can leave the release in a broken state"
        )

    def test_uses_hatch_build(self):
        """hatch is already the build backend; the workflow should use it."""
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "hatch build" in content, (
            "publish.yml should build with 'hatch build' — consistent with pyproject.toml "
            "which uses hatchling as the build-backend"
        )

    def test_runs_twine_check(self):
        """twine check catches malformed metadata before upload."""
        content = PUBLISH_YML.read_text(encoding="utf-8")
        assert "twine check" in content, (
            "publish.yml should run 'twine check dist/*' after building "
            "to catch malformed package metadata before uploading to PyPI"
        )


# ===========================================================================
# TestPreCommitConfig
# ===========================================================================


class TestPreCommitConfig:
    """Guards .pre-commit-config.yaml."""

    def test_file_exists(self):
        assert PRE_COMMIT_CFG.exists(), (
            f"{PRE_COMMIT_CFG} not found — pre-commit is listed as a dev dep "
            "in pyproject.toml but has no config; create .pre-commit-config.yaml"
        )

    def test_parses_as_valid_yaml(self):
        data = _load_yaml(PRE_COMMIT_CFG)
        assert isinstance(data, dict), ".pre-commit-config.yaml must be a YAML mapping"

    def test_has_repos_key(self):
        data = _load_yaml(PRE_COMMIT_CFG)
        assert "repos" in data, ".pre-commit-config.yaml must have a top-level 'repos' key"

    def test_repos_is_list(self):
        data = _load_yaml(PRE_COMMIT_CFG)
        assert isinstance(data.get("repos"), list), "'repos' must be a list of hook repos"

    def test_has_ruff_hook(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "ruff" in content, (
            ".pre-commit-config.yaml must include ruff hooks — ruff is already "
            "the configured linter/formatter in pyproject.toml"
        )

    def test_uses_astral_ruff_pre_commit(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "astral-sh/ruff-pre-commit" in content, "use the official astral-sh/ruff-pre-commit repo for ruff hooks"

    def test_has_ruff_format_hook(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "ruff-format" in content, ".pre-commit-config.yaml must include ruff-format so commits stay formatted"

    def test_has_yaml_check(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "check-yaml" in content, (
            ".pre-commit-config.yaml should include check-yaml to catch broken workflow files"
        )

    def test_has_toml_check(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "check-toml" in content, (
            ".pre-commit-config.yaml should include check-toml to catch malformed pyproject.toml"
        )

    def test_has_end_of_file_fixer(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "end-of-file-fixer" in content, (
            ".pre-commit-config.yaml should include end-of-file-fixer for consistent line endings"
        )

    def test_has_merge_conflict_check(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "check-merge-conflict" in content, (
            ".pre-commit-config.yaml should include check-merge-conflict to prevent committing unresolved merge markers"
        )

    def test_ruff_hook_has_fix_arg(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "--fix" in content, "ruff hook should include '--fix' to auto-correct lint violations on commit"

    def test_rev_pinned_for_ruff(self):
        """ruff hook must have a pinned rev (not 'latest')."""
        data = _load_yaml(PRE_COMMIT_CFG)
        for repo in data.get("repos", []):
            if "ruff" in repo.get("repo", ""):
                rev = repo.get("rev", "")
                assert rev and rev != "latest", f"ruff-pre-commit rev must be pinned (e.g. 'v0.4.4'), got: {rev!r}"
                assert rev.startswith("v"), f"ruff-pre-commit rev should start with 'v', got: {rev!r}"

    def test_debug_statements_hook(self):
        content = PRE_COMMIT_CFG.read_text(encoding="utf-8")
        assert "debug-statements" in content, (
            ".pre-commit-config.yaml should include debug-statements hook to prevent "
            "committing stray pdb.set_trace() / breakpoint() calls"
        )
