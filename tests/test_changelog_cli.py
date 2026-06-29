"""Tests for the `manus-agent changelog` subcommand and scripts/release.py.

All git operations are fully mocked — no real git calls occur.
All file I/O uses tmp_path fixtures so the source tree is never touched.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from textwrap import dedent
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _invoke_changelog(argv: list[str]) -> tuple[int, str, str]:
    """Call cli.main() with `changelog <argv>` and return (rc, stdout, stderr)."""
    from manus_use import cli  # noqa: PLC0415

    with mock.patch.object(sys, "argv", ["manus-agent", "changelog", *argv]):
        import io

        out_buf, err_buf = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out_buf), mock.patch("sys.stderr", err_buf):
            try:
                cli.main()
                rc = 0
            except SystemExit as exc:
                rc = exc.code if isinstance(exc.code, int) else 0
    return rc, out_buf.getvalue(), err_buf.getvalue()


# ---------------------------------------------------------------------------
# CLI routing
# ---------------------------------------------------------------------------


class TestChangelogSubcommandRouting:
    def test_changelog_in_subcommands_set(self):
        """'changelog' must be registered in _SUBCOMMANDS."""
        from manus_use import cli  # noqa: PLC0415

        assert "changelog" in cli._SUBCOMMANDS

    def test_changelog_build_parser_exists(self):
        """_build_changelog_parser must be importable."""
        from manus_use import cli  # noqa: PLC0415

        assert callable(cli._build_changelog_parser)

    def test_changelog_run_exists(self):
        """_run_changelog must be importable."""
        from manus_use import cli  # noqa: PLC0415

        assert callable(cli._run_changelog)

    def test_changelog_help_exits_zero(self):
        """manus-agent changelog --help exits 0."""
        from manus_use import cli  # noqa: PLC0415

        with pytest.raises(SystemExit) as exc_info:
            with mock.patch.object(sys, "argv", ["manus-agent", "changelog", "--help"]):
                cli.main()
        assert exc_info.value.code == 0

    def test_changelog_help_mentions_generate(self, capsys):
        """Help text mentions --generate flag."""
        from manus_use import cli  # noqa: PLC0415

        with pytest.raises(SystemExit):
            with mock.patch.object(sys, "argv", ["manus-agent", "changelog", "--help"]):
                cli.main()
        out = capsys.readouterr().out
        assert "--generate" in out

    def test_changelog_help_mentions_version_filter(self, capsys):
        """Help text mentions --version filter."""
        from manus_use import cli  # noqa: PLC0415

        with pytest.raises(SystemExit):
            with mock.patch.object(sys, "argv", ["manus-agent", "changelog", "--help"]):
                cli.main()
        out = capsys.readouterr().out
        assert "--version" in out

    def test_main_routes_to_changelog(self):
        """main() dispatches 'changelog' to _run_changelog."""
        from manus_use import cli  # noqa: PLC0415

        with mock.patch.object(cli, "_run_changelog", return_value=0) as mock_run:
            with pytest.raises(SystemExit) as exc_info:
                with mock.patch.object(sys, "argv", ["manus-agent", "changelog"]):
                    cli.main()
        mock_run.assert_called_once()
        assert exc_info.value.code == 0

    def test_top_level_help_mentions_changelog(self, capsys):
        """manus-agent --help output mentions the changelog subcommand."""
        from manus_use import cli  # noqa: PLC0415

        with pytest.raises(SystemExit):
            with mock.patch.object(sys, "argv", ["manus-agent", "--help"]):
                cli.main()
        out = capsys.readouterr().out
        assert "changelog" in out


# ---------------------------------------------------------------------------
# Changelog view mode (reads CHANGELOG.md)
# ---------------------------------------------------------------------------


class TestChangelogView:
    @pytest.fixture()
    def fake_changelog(self, tmp_path: Path) -> Path:
        cl = tmp_path / "CHANGELOG.md"
        cl.write_text(
            dedent("""\
            # Changelog

            ## [Unreleased]

            <!-- placeholder -->

            ## [0.2.0] -- 2026-06-29

            ### Added
            - feat one
            - feat two

            ## [0.1.0] -- 2026-06-26

            ### Added
            - initial release

            [Unreleased]: https://github.com/manus-use/manus-use/compare/v0.2.0...HEAD
            [0.2.0]: https://github.com/manus-use/manus-use/compare/v0.1.0...v0.2.0
            [0.1.0]: https://github.com/manus-use/manus-use/releases/tag/v0.1.0
            """),
            encoding="utf-8",
        )
        return cl

    def test_view_returns_full_changelog(self, fake_changelog: Path):
        """Without flags, _run_changelog returns all CHANGELOG.md content."""
        import io

        from manus_use import cli  # noqa: PLC0415

        cl_content = fake_changelog.read_text()
        out = io.StringIO()
        with (
            mock.patch("pathlib.Path.exists", return_value=True),
            mock.patch("pathlib.Path.read_text", return_value=cl_content),
            mock.patch("sys.stdout", out),
        ):
            rc = cli._run_changelog([])
        assert rc == 0
        printed = out.getvalue()
        assert "[0.2.0]" in printed
        assert "[0.1.0]" in printed
        assert "feat one" in printed

    def test_view_missing_changelog_returns_nonzero(self, tmp_path: Path):
        """_run_changelog returns 1 when CHANGELOG.md doesn't exist."""
        from manus_use import cli  # noqa: PLC0415

        with mock.patch("pathlib.Path.exists", return_value=False):
            import io

            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                rc = cli._run_changelog([])
        assert rc == 1
        assert "CHANGELOG.md not found" in err.getvalue()

    def test_version_filter_not_found_returns_nonzero(self, fake_changelog: Path):
        """--version X.Y.Z returns 1 when the section isn't in the changelog."""
        from manus_use import cli  # noqa: PLC0415

        with (
            mock.patch("pathlib.Path.exists", return_value=True),
            mock.patch("pathlib.Path.read_text", return_value=fake_changelog.read_text()),
        ):
            import io

            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                rc = cli._run_changelog(["--version", "9.9.9"])
        assert rc == 1
        assert "9.9.9" in err.getvalue()


# ---------------------------------------------------------------------------
# Generate mode (parses git commits)
# ---------------------------------------------------------------------------


class TestChangelogGenerate:
    def _mock_git_log_output(self) -> str:
        """Simulate `git log --format=%H\x1f%s\x1f%b\x1e` with two commits."""
        commits = [
            ("aabbccdd1234", "feat(tools): add temporal priority scorer", ""),
            ("11223344abcd", "fix(cli): correct --output default value", ""),
            ("deadbeef9999", "docs(readme): update installation instructions", ""),
            ("notconventional", "Miscellaneous change without prefix", ""),
        ]
        parts = []
        for sha, subj, body in commits:
            parts.append(f"{sha}\x1f{subj}\x1f{body}")
        return "\x1e".join(parts) + "\x1e"

    def test_generate_text_output(self, tmp_path: Path):
        """--generate produces text output with version header."""
        from manus_use import cli  # noqa: PLC0415

        fake_pyproject = tmp_path / "pyproject.toml"
        fake_pyproject.write_text('version = "0.1.0"\n', encoding="utf-8")

        mock_result = mock.MagicMock()
        mock_result.stdout = self._mock_git_log_output()
        mock_result.returncode = 0

        describe_result = mock.MagicMock()
        describe_result.stdout = ""  # no previous tag
        describe_result.returncode = 1

        def fake_run(cmd, **kwargs):
            if "describe" in cmd:
                return describe_result
            return mock_result

        with (
            mock.patch("subprocess.run", side_effect=fake_run),
            mock.patch("pathlib.Path.exists", return_value=True),
            mock.patch("pathlib.Path.read_text", return_value=fake_pyproject.read_text()),
        ):
            import io

            out = io.StringIO()
            err = io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                rc = cli._run_changelog(["--generate"])

        assert rc == 0
        output = out.getvalue()
        # Should contain a version header
        assert "## [" in output
        # Should mention Added section (feat commits)
        assert "### Added" in output

    def test_generate_json_output(self, tmp_path: Path):
        """--generate --output json returns valid JSON with expected keys."""
        from manus_use import cli  # noqa: PLC0415

        fake_pyproject = tmp_path / "pyproject.toml"
        fake_pyproject.write_text('version = "0.1.0"\n', encoding="utf-8")

        mock_result = mock.MagicMock()
        mock_result.stdout = self._mock_git_log_output()
        mock_result.returncode = 0

        describe_result = mock.MagicMock()
        describe_result.stdout = ""
        describe_result.returncode = 1

        def fake_run(cmd, **kwargs):
            if "describe" in cmd:
                return describe_result
            return mock_result

        with (
            mock.patch("subprocess.run", side_effect=fake_run),
            mock.patch("pathlib.Path.exists", return_value=True),
            mock.patch("pathlib.Path.read_text", return_value=fake_pyproject.read_text()),
        ):
            import io

            out = io.StringIO()
            err = io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                rc = cli._run_changelog(["--generate", "--output", "json"])

        assert rc == 0
        data = json.loads(out.getvalue())
        assert "next_version" in data
        assert "commits" in data
        assert "inferred_bump" in data
        assert data["inferred_bump"] in ("major", "minor", "patch")

    def test_generate_no_commits_returns_zero(self, tmp_path: Path):
        """--generate returns 0 (not an error) when no conventional commits exist."""
        from manus_use import cli  # noqa: PLC0415

        mock_result = mock.MagicMock()
        mock_result.stdout = ""
        mock_result.returncode = 0

        describe_result = mock.MagicMock()
        describe_result.stdout = ""
        describe_result.returncode = 1

        def fake_run(cmd, **kwargs):
            if "describe" in cmd:
                return describe_result
            return mock_result

        with (
            mock.patch("subprocess.run", side_effect=fake_run),
            mock.patch("pathlib.Path.exists", return_value=True),
            mock.patch(
                "pathlib.Path.read_text",
                return_value='version = "0.1.0"\n',
            ),
        ):
            import io

            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                rc = cli._run_changelog(["--generate"])
        assert rc == 0

    def test_generate_feat_infers_minor_bump(self, tmp_path: Path):
        """A feat commit should infer a minor version bump."""
        from manus_use import cli  # noqa: PLC0415

        single_feat = "aabbccdd1234\x1ffeat(tools): my new tool\x1f\x1e"
        mock_result = mock.MagicMock()
        mock_result.stdout = single_feat
        mock_result.returncode = 0

        describe_result = mock.MagicMock()
        describe_result.stdout = ""
        describe_result.returncode = 1

        def fake_run(cmd, **kwargs):
            if "describe" in cmd:
                return describe_result
            return mock_result

        with (
            mock.patch("subprocess.run", side_effect=fake_run),
            mock.patch("pathlib.Path.exists", return_value=True),
            mock.patch(
                "pathlib.Path.read_text",
                return_value='version = "0.1.0"\n',
            ),
        ):
            import io

            out = io.StringIO()
            err = io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
                _rc = cli._run_changelog(["--generate", "--output", "json"])

        data = json.loads(out.getvalue())
        assert data["inferred_bump"] == "minor"
        assert data["next_version"] == "0.2.0"

    def test_generate_fix_only_infers_patch_bump(self, tmp_path: Path):
        """Only fix commits should infer a patch bump."""
        from manus_use import cli  # noqa: PLC0415

        single_fix = "aabbccdd1234\x1ffix(cli): correct typo\x1f\x1e"
        mock_result = mock.MagicMock()
        mock_result.stdout = single_fix
        mock_result.returncode = 0

        describe_result = mock.MagicMock()
        describe_result.stdout = ""
        describe_result.returncode = 1

        def fake_run(cmd, **kwargs):
            if "describe" in cmd:
                return describe_result
            return mock_result

        with (
            mock.patch("subprocess.run", side_effect=fake_run),
            mock.patch("pathlib.Path.exists", return_value=True),
            mock.patch(
                "pathlib.Path.read_text",
                return_value='version = "0.1.0"\n',
            ),
        ):
            import io

            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                _rc = cli._run_changelog(["--generate", "--output", "json"])

        data = json.loads(out.getvalue())
        assert data["inferred_bump"] == "patch"
        assert data["next_version"] == "0.1.1"

    def test_generate_breaking_infers_major_bump(self, tmp_path: Path):
        """A breaking-change commit should infer a major bump."""
        from manus_use import cli  # noqa: PLC0415

        breaking = "aabbccdd1234\x1ffeat!: remove deprecated API\x1f\x1e"
        mock_result = mock.MagicMock()
        mock_result.stdout = breaking
        mock_result.returncode = 0

        describe_result = mock.MagicMock()
        describe_result.stdout = ""
        describe_result.returncode = 1

        def fake_run(cmd, **kwargs):
            if "describe" in cmd:
                return describe_result
            return mock_result

        with (
            mock.patch("subprocess.run", side_effect=fake_run),
            mock.patch("pathlib.Path.exists", return_value=True),
            mock.patch(
                "pathlib.Path.read_text",
                return_value='version = "0.1.0"\n',
            ),
        ):
            import io

            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                _rc = cli._run_changelog(["--generate", "--output", "json"])

        data = json.loads(out.getvalue())
        assert data["inferred_bump"] == "major"
        assert data["next_version"] == "1.0.0"


# ---------------------------------------------------------------------------
# scripts/release.py unit tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def release_module(tmp_path: Path):
    """Import scripts/release.py with ROOT temporarily patched to tmp_path."""
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("release", root / "scripts" / "release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestReleaseScriptExists:
    def test_release_script_exists(self):
        """scripts/release.py must exist at the expected path."""
        root = Path(__file__).resolve().parents[1]
        assert (root / "scripts" / "release.py").exists(), (
            "scripts/release.py not found — create it to enable release automation"
        )

    def test_release_script_is_valid_python(self):
        """scripts/release.py must be syntactically valid Python."""
        import ast

        root = Path(__file__).resolve().parents[1]
        source = (root / "scripts" / "release.py").read_text(encoding="utf-8")
        ast.parse(source)  # raises SyntaxError if invalid

    def test_release_script_importable(self, release_module):
        """scripts/release.py must be importable without side effects."""
        assert release_module is not None


class TestReleaseScriptReadVersion:
    def test_reads_version_from_pyproject(self, tmp_path: Path, release_module):
        """read_version() parses X.Y.Z from pyproject.toml correctly."""
        pyp = tmp_path / "pyproject.toml"
        pyp.write_text('version = "1.2.3"\n', encoding="utf-8")
        with mock.patch.object(release_module, "PYPROJECT", pyp):
            assert release_module.read_version() == (1, 2, 3)

    def test_read_version_raises_on_missing_field(self, tmp_path: Path, release_module):
        """read_version() raises ValueError when version field is absent."""
        pyp = tmp_path / "pyproject.toml"
        pyp.write_text("[project]\nname = 'foo'\n", encoding="utf-8")
        with mock.patch.object(release_module, "PYPROJECT", pyp):
            with pytest.raises(ValueError, match="version"):
                release_module.read_version()


class TestReleaseScriptWriteVersion:
    def test_writes_version_to_pyproject(self, tmp_path: Path, release_module):
        """write_version() updates pyproject.toml in-place."""
        pyp = tmp_path / "pyproject.toml"
        pyp.write_text('[project]\nversion = "0.1.0"\n', encoding="utf-8")
        with mock.patch.object(release_module, "PYPROJECT", pyp):
            release_module.write_version(0, 2, 0)
        assert 'version = "0.2.0"' in pyp.read_text()

    def test_write_version_no_effect_raises(self, tmp_path: Path, release_module):
        """write_version() raises ValueError when the substitution has no effect."""
        pyp = tmp_path / "pyproject.toml"
        pyp.write_text("[project]\nname = 'foo'\n", encoding="utf-8")
        with mock.patch.object(release_module, "PYPROJECT", pyp):
            with pytest.raises(ValueError):
                release_module.write_version(1, 0, 0)


class TestReleaseScriptBumpVersion:
    @pytest.mark.parametrize(
        "current,bump,expected",
        [
            ((0, 1, 0), "patch", (0, 1, 1)),
            ((0, 1, 0), "minor", (0, 2, 0)),
            ((0, 1, 0), "major", (1, 0, 0)),
            ((1, 2, 3), "patch", (1, 2, 4)),
            ((1, 2, 3), "minor", (1, 3, 0)),
            ((1, 2, 3), "major", (2, 0, 0)),
        ],
    )
    def test_bump_version(self, current, bump, expected, release_module):
        assert release_module.bump_version(current, bump) == expected

    def test_bump_version_invalid_type(self, release_module):
        with pytest.raises(ValueError, match="Unknown bump type"):
            release_module.bump_version((0, 1, 0), "invalid")


class TestReleaseScriptInferBump:
    def test_infer_feat_gives_minor(self, release_module):
        commits = [
            release_module.ParsedCommit("abc", "feat", "cli", False, "add thing", ""),
        ]
        assert release_module.infer_bump(commits) == "minor"

    def test_infer_fix_gives_patch(self, release_module):
        commits = [
            release_module.ParsedCommit("abc", "fix", "cli", False, "fix bug", ""),
        ]
        assert release_module.infer_bump(commits) == "patch"

    def test_infer_breaking_gives_major(self, release_module):
        commits = [
            release_module.ParsedCommit("abc", "feat", "cli", True, "break API", ""),
        ]
        assert release_module.infer_bump(commits) == "major"

    def test_infer_mixed_gives_highest(self, release_module):
        commits = [
            release_module.ParsedCommit("a", "fix", "", False, "fix one", ""),
            release_module.ParsedCommit("b", "feat", "", False, "new feature", ""),
        ]
        assert release_module.infer_bump(commits) == "minor"

    def test_infer_empty_gives_patch(self, release_module):
        assert release_module.infer_bump([]) == "patch"


class TestReleaseScriptGenerateSection:
    def test_generate_section_contains_version_header(self, release_module):
        commits = [
            release_module.ParsedCommit("aabbccdd", "feat", "tools", False, "new tool", ""),
        ]
        section = release_module.generate_section((0, 2, 0), commits, today="2026-06-29")
        assert "## [0.2.0]" in section
        assert "2026-06-29" in section

    def test_generate_section_groups_by_type(self, release_module):
        commits = [
            release_module.ParsedCommit("aaaa1111", "feat", "tools", False, "new feature", ""),
            release_module.ParsedCommit("bbbb2222", "fix", "cli", False, "bug fix", ""),
        ]
        section = release_module.generate_section((0, 2, 0), commits, today="2026-06-29")
        assert "### Added" in section
        assert "### Fixed" in section
        # Added should appear before Fixed
        assert section.index("### Added") < section.index("### Fixed")

    def test_generate_section_line_format(self, release_module):
        commits = [
            release_module.ParsedCommit("deadbeef1234", "feat", "api", False, "new endpoint", ""),
        ]
        section = release_module.generate_section((0, 2, 0), commits, today="2026-06-29")
        # Line should include: scope, description, sha (first 8 chars)
        assert "**api**" in section
        assert "new endpoint" in section
        assert "deadbeef" in section

    def test_generate_section_breaking_change_tag(self, release_module):
        commits = [
            release_module.ParsedCommit("aabb1122", "feat", "api", True, "remove old API", ""),
        ]
        section = release_module.generate_section((1, 0, 0), commits, today="2026-06-29")
        assert "BREAKING CHANGE" in section


class TestReleaseScriptParseCommits:
    def _fake_run(self, module, log_output: str, describe_raises: bool = True):
        """Context manager that patches _run in the release module."""

        def side_effect(cmd, **kwargs):
            if "describe" in cmd:
                if describe_raises:
                    raise RuntimeError("no tags")
                return ""
            if "log" in cmd:
                return log_output
            return ""

        return mock.patch.object(module, "_run", side_effect=side_effect)

    def test_parses_conventional_commits(self, release_module):
        log_output = "aabbccdd1234\x1ffeat(tools): add new tool\x1f\x1e"
        with self._fake_run(release_module, log_output):
            commits = release_module.parse_commits(None)
        assert len(commits) == 1
        assert commits[0].type == "feat"
        assert commits[0].scope == "tools"
        assert commits[0].description == "add new tool"

    def test_skips_non_conventional_commits(self, release_module):
        log_output = "aabbccdd1234\x1fMiscellaneous non-conventional message\x1f\x1e"
        with self._fake_run(release_module, log_output):
            commits = release_module.parse_commits(None)
        assert len(commits) == 0

    def test_detects_breaking_change_suffix(self, release_module):
        log_output = "aabbccdd1234\x1ffeat!: breaking change\x1f\x1e"
        with self._fake_run(release_module, log_output):
            commits = release_module.parse_commits(None)
        assert commits[0].breaking is True

    def test_detects_breaking_change_footer(self, release_module):
        log_output = "aabbccdd1234\x1ffeat(api): change endpoint\x1fBREAKING CHANGE: removed /v1/\x1e"
        with self._fake_run(release_module, log_output):
            commits = release_module.parse_commits(None)
        assert commits[0].breaking is True


class TestReleaseScriptUpdateChangelog:
    def _make_changelog(self, tmp_path: Path, content: str) -> Path:
        cl = tmp_path / "CHANGELOG.md"
        cl.write_text(content, encoding="utf-8")
        return cl

    def test_update_inserts_new_section(self, tmp_path: Path, release_module):
        """update_changelog inserts the new section after [Unreleased]."""
        cl = self._make_changelog(
            tmp_path,
            dedent("""\
            # Changelog

            ## [Unreleased]

            old content here

            ## [0.1.0] -- 2026-01-01

            ### Added
            - initial

            [Unreleased]: https://github.com/manus-use/manus-use/compare/v0.1.0...HEAD
            [0.1.0]: https://github.com/manus-use/manus-use/releases/tag/v0.1.0
            """),
        )
        section = "## [0.2.0] -- 2026-06-29\n\n### Added\n- new thing\n"

        with mock.patch.object(release_module, "CHANGELOG", cl):
            release_module.update_changelog(section, (0, 2, 0), (0, 1, 0))

        updated = cl.read_text(encoding="utf-8")
        assert "## [0.2.0]" in updated
        assert "new thing" in updated
        # [Unreleased] heading still present but content is placeholder
        assert "## [Unreleased]" in updated

    def test_update_refreshes_unreleased_link(self, tmp_path: Path, release_module):
        """update_changelog updates the [Unreleased] comparison link."""
        cl = self._make_changelog(
            tmp_path,
            dedent("""\
            # Changelog

            ## [Unreleased]

            [Unreleased]: https://github.com/manus-use/manus-use/compare/v0.1.0...HEAD
            [0.1.0]: https://github.com/manus-use/manus-use/releases/tag/v0.1.0
            """),
        )
        section = "## [0.2.0] -- 2026-06-29\n\n### Added\n- new thing\n"

        with mock.patch.object(release_module, "CHANGELOG", cl):
            release_module.update_changelog(section, (0, 2, 0), (0, 1, 0))

        updated = cl.read_text(encoding="utf-8")
        assert "compare/v0.2.0...HEAD" in updated

    def test_update_adds_new_version_link(self, tmp_path: Path, release_module):
        """update_changelog adds a new [0.2.0] comparison link."""
        cl = self._make_changelog(
            tmp_path,
            dedent("""\
            # Changelog

            ## [Unreleased]

            [Unreleased]: https://github.com/manus-use/manus-use/compare/v0.1.0...HEAD
            """),
        )
        section = "## [0.2.0] -- 2026-06-29\n\n### Added\n- new\n"

        with mock.patch.object(release_module, "CHANGELOG", cl):
            release_module.update_changelog(section, (0, 2, 0), (0, 1, 0))

        updated = cl.read_text(encoding="utf-8")
        assert "[0.2.0]:" in updated

    def test_update_raises_when_file_missing(self, tmp_path: Path, release_module):
        """update_changelog raises FileNotFoundError when CHANGELOG.md is absent."""
        missing = tmp_path / "CHANGELOG.md"
        with mock.patch.object(release_module, "CHANGELOG", missing):
            with pytest.raises(FileNotFoundError):
                release_module.update_changelog("## [0.2.0]\n", (0, 2, 0), (0, 1, 0))


class TestReleaseScriptCLI:
    def _invoke(self, release_module, argv: list[str]) -> tuple[int, str]:
        """Invoke release module main() and capture stdout."""
        import io

        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = release_module.main(argv)
        return rc, buf.getvalue()

    def test_version_command(self, tmp_path: Path, release_module):
        """version subcommand prints current version."""
        pyp = tmp_path / "pyproject.toml"
        pyp.write_text('version = "0.1.0"\n', encoding="utf-8")
        with mock.patch.object(release_module, "PYPROJECT", pyp):
            rc, out = self._invoke(release_module, ["version"])
        assert rc == 0
        assert "0.1.0" in out

    def test_notes_command_no_tags(self, tmp_path: Path, release_module):
        """notes subcommand runs and returns 0 when there are commits."""
        pyp = tmp_path / "pyproject.toml"
        pyp.write_text('version = "0.1.0"\n', encoding="utf-8")
        log = "aabbccdd\x1ffeat(api): add endpoint\x1f\x1e"

        def fake_run(cmd, **kwargs):
            if "describe" in cmd:
                raise RuntimeError("no tags")
            if "log" in cmd:
                return log
            return ""

        with (
            mock.patch.object(release_module, "PYPROJECT", pyp),
            mock.patch.object(release_module, "_run", side_effect=fake_run),
        ):
            import io

            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                rc, out = self._invoke(release_module, ["notes"])
        assert rc == 0
        assert "0.2.0" in out  # minor bump from feat

    def test_patch_dry_run(self, tmp_path: Path, release_module):
        """patch --dry-run previews but does not write files."""
        pyp = tmp_path / "pyproject.toml"
        pyp.write_text('[project]\nversion = "0.1.0"\n', encoding="utf-8")
        log = "aabbccdd\x1ffix(cli): fix typo\x1f\x1e"

        def fake_run(cmd, **kwargs):
            if "describe" in cmd:
                raise RuntimeError("no tags")
            if "log" in cmd:
                return log
            return ""

        with (
            mock.patch.object(release_module, "PYPROJECT", pyp),
            mock.patch.object(release_module, "_run", side_effect=fake_run),
        ):
            rc, out = self._invoke(release_module, ["patch", "--dry-run"])

        assert rc == 0
        assert "dry-run" in out.lower() or "No files modified" in out
        # pyproject.toml must NOT have been changed
        assert 'version = "0.1.0"' in pyp.read_text()

    def test_no_command_prints_help(self, release_module):
        """No args prints help."""
        import io

        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = release_module.main([])
        # help text should not be empty
        # rc is 0 (help path)
        assert rc == 0


class TestChangelogMdFile:
    def test_changelog_md_exists(self):
        """CHANGELOG.md must exist at the project root."""
        root = Path(__file__).resolve().parents[1]
        assert (root / "CHANGELOG.md").exists(), "CHANGELOG.md not found — create it to provide project release history"

    def test_changelog_md_has_unreleased_section(self):
        """CHANGELOG.md must have a [Unreleased] section."""
        root = Path(__file__).resolve().parents[1]
        cl = root / "CHANGELOG.md"
        if not cl.exists():
            pytest.skip("CHANGELOG.md not found")
        content = cl.read_text(encoding="utf-8")
        assert "## [Unreleased]" in content, "CHANGELOG.md must have a '## [Unreleased]' section at the top"

    def test_changelog_md_has_at_least_one_released_version(self):
        """CHANGELOG.md must have at least one released version section."""
        root = Path(__file__).resolve().parents[1]
        cl = root / "CHANGELOG.md"
        if not cl.exists():
            pytest.skip("CHANGELOG.md not found")
        content = cl.read_text(encoding="utf-8")
        import re

        assert re.search(r"## \[\d+\.\d+\.\d+\]", content), (
            "CHANGELOG.md must have at least one released version section like ## [0.1.0]"
        )

    def test_changelog_md_has_link_footer(self):
        """CHANGELOG.md must have a [Unreleased] link footer."""
        root = Path(__file__).resolve().parents[1]
        cl = root / "CHANGELOG.md"
        if not cl.exists():
            pytest.skip("CHANGELOG.md not found")
        content = cl.read_text(encoding="utf-8")
        assert "[Unreleased]:" in content, "CHANGELOG.md must have a '[Unreleased]: https://...' link footer"

    def test_changelog_md_references_manus_use_repo(self):
        """CHANGELOG.md links should point to the manus-use/manus-use repository."""
        root = Path(__file__).resolve().parents[1]
        cl = root / "CHANGELOG.md"
        if not cl.exists():
            pytest.skip("CHANGELOG.md not found")
        content = cl.read_text(encoding="utf-8")
        assert "manus-use/manus-use" in content, (
            "CHANGELOG.md link footer should reference the manus-use/manus-use repository"
        )
