"""Tests verifying that the GitHub Actions CI workflow and CONTRIBUTING.md exist and are valid.

These are "living documentation" tests — they ensure the infrastructure files
stay present and structurally sound as the project evolves.
"""

from __future__ import annotations

import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
TEST_YML = WORKFLOWS_DIR / "test.yml"
CONTRIBUTING_MD = REPO_ROOT / "CONTRIBUTING.md"


# ---------------------------------------------------------------------------
# GitHub Actions CI workflow
# ---------------------------------------------------------------------------


class TestCIWorkflow:
    """The test.yml CI workflow must exist and contain required configuration."""

    def test_workflow_file_exists(self):
        """.github/workflows/test.yml must exist (README badge points to it)."""
        assert TEST_YML.exists(), (
            f"CI workflow not found at {TEST_YML}. "
            "The README badge references this file — create it or the badge will always show 'unknown'."
        )

    def test_workflow_triggers_on_push_to_main(self):
        """Workflow must run on push to main."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "push:" in content
        assert "main" in content

    def test_workflow_triggers_on_pull_request(self):
        """Workflow must run on pull_request events."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "pull_request:" in content

    def test_workflow_has_lint_job(self):
        """Workflow must include a lint/ruff job."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "ruff" in content.lower(), "Workflow must run ruff lint"

    def test_workflow_has_test_job(self):
        """Workflow must include a pytest job."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "pytest" in content, "Workflow must run pytest"

    def test_workflow_tests_multiple_python_versions(self):
        """Workflow should test on at least two Python versions."""
        content = TEST_YML.read_text(encoding="utf-8")
        # Should contain at least 3.11 and 3.12
        assert "3.11" in content, "Workflow should test Python 3.11"
        assert "3.12" in content, "Workflow should test Python 3.12"

    def test_workflow_excludes_integration_tests(self):
        """Workflow must not run integration tests (they require live credentials)."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "not integration" in content, (
            "Workflow must pass -m 'not integration' to pytest so integration tests don't run in CI without credentials"
        )

    def test_workflow_uses_checkout_action(self):
        """Workflow must use actions/checkout."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "actions/checkout" in content

    def test_workflow_uses_setup_python_action(self):
        """Workflow must use actions/setup-python."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "actions/setup-python" in content

    def test_workflow_installs_package(self):
        """Workflow must install the package (pip install -e or similar)."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "pip install" in content, "Workflow must install the package before testing"

    def test_workflow_has_concurrency_group(self):
        """Workflow should cancel redundant runs via concurrency group."""
        content = TEST_YML.read_text(encoding="utf-8")
        assert "concurrency:" in content, "Workflow should set a concurrency group to cancel stale runs on force-push"

    def test_workflow_is_valid_yaml(self):
        """test.yml must be parseable as YAML."""
        try:
            import yaml  # type: ignore[import]
        except ImportError:
            pytest.skip("PyYAML not installed — skipping YAML parse check")

        content = TEST_YML.read_text(encoding="utf-8")
        doc = yaml.safe_load(content)
        assert isinstance(doc, dict), "Workflow YAML must parse to a dict"
        assert "jobs" in doc, "Workflow must define at least one job"
        # YAML parses bare `on:` as the Python boolean True, not the string "on".
        # Accept either form so the test is robust to different PyYAML versions.
        assert "on" in doc or True in doc, "Workflow must define trigger events"


# ---------------------------------------------------------------------------
# README badge cross-reference
# ---------------------------------------------------------------------------


def test_readme_badge_references_test_yml():
    """README.md badge URL must reference the test.yml workflow that actually exists."""
    readme = REPO_ROOT / "README.md"
    assert readme.exists(), "README.md not found"

    content = readme.read_text(encoding="utf-8")
    # The badge should point to the workflows/test.yml file
    assert "test.yml" in content, (
        "README.md badge should reference workflows/test.yml. If the workflow was renamed, update the badge URL too."
    )


# ---------------------------------------------------------------------------
# CONTRIBUTING.md
# ---------------------------------------------------------------------------


class TestContributing:
    """CONTRIBUTING.md must exist and cover the key onboarding topics."""

    def test_contributing_file_exists(self):
        """CONTRIBUTING.md must be present at the repository root."""
        assert CONTRIBUTING_MD.exists(), (
            "CONTRIBUTING.md not found. New contributors need guidance on dev setup, testing, and PR conventions."
        )

    def test_contributing_covers_dev_setup(self):
        """CONTRIBUTING.md must cover development environment setup."""
        content = CONTRIBUTING_MD.read_text(encoding="utf-8")
        # Should mention pip install -e or editable install
        assert "pip install" in content, "Must document how to install the package for development"

    def test_contributing_covers_testing(self):
        """CONTRIBUTING.md must explain how to run tests."""
        content = CONTRIBUTING_MD.read_text(encoding="utf-8")
        assert "pytest" in content, "Must document how to run the test suite"

    def test_contributing_covers_linting(self):
        """CONTRIBUTING.md must mention the ruff linter."""
        content = CONTRIBUTING_MD.read_text(encoding="utf-8")
        assert "ruff" in content.lower(), "Must document the ruff linter"

    def test_contributing_covers_conventional_commits(self):
        """CONTRIBUTING.md should document Conventional Commits format."""
        content = CONTRIBUTING_MD.read_text(encoding="utf-8")
        assert "conventional" in content.lower() or "feat(" in content, (
            "Must document the Conventional Commits style used in this repo"
        )

    def test_contributing_warns_against_src_imports(self):
        """CONTRIBUTING.md should warn against 'from src.manus_use' imports."""
        content = CONTRIBUTING_MD.read_text(encoding="utf-8")
        assert "src." in content or "from src" in content, (
            "Should warn contributors not to use 'from src.manus_use.' imports"
        )

    def test_contributing_not_empty(self):
        """CONTRIBUTING.md must have substantial content (> 500 chars)."""
        content = CONTRIBUTING_MD.read_text(encoding="utf-8")
        assert len(content) > 500, "CONTRIBUTING.md appears too short to be useful"
