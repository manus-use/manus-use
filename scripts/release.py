#!/usr/bin/env python3
"""Release helper for manus-use.

Usage
-----
    # Dry-run: preview what the next release would look like
    python scripts/release.py --dry-run

    # Bump patch version, update CHANGELOG, commit, tag, and push
    python scripts/release.py patch

    # Bump minor version
    python scripts/release.py minor

    # Bump major version
    python scripts/release.py major

    # Just generate release notes from recent commits (no file changes)
    python scripts/release.py notes

    # Print the current version and exit
    python scripts/release.py version

Conventional commit prefixes recognised
-----------------------------------------
    feat     -> Minor bump (new feature)
    fix      -> Patch bump
    docs     -> Patch bump
    test     -> Patch bump
    refactor -> Patch bump
    perf     -> Patch bump
    chore    -> Patch bump
    ci       -> Patch bump
    BREAKING CHANGE (footer) or ``!`` suffix -> Major bump

The script reads commits since the last ``v*`` tag (or all commits when no
tags exist).  Each commit is parsed into a section:

    ## [<new-version>] -- YYYY-MM-DD
    ### Added / Changed / Fixed / Other

The generated section is inserted after the ``## [Unreleased]`` heading in
CHANGELOG.md.  The ``[Unreleased]`` content is reset to a placeholder.

Version is read from / written to ``pyproject.toml``.

Dependencies
------------
Only the standard library is required.  ``git`` and ``gh`` (GitHub CLI) must
be available on PATH for tagging and GitHub-release steps.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"

# ---------------------------------------------------------------------------
# Conventional commit parsing
# ---------------------------------------------------------------------------

_CC_PATTERN = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?(?P<breaking>!)?: (?P<desc>.+)$",
    re.MULTILINE,
)

_BREAKING_FOOTER = re.compile(r"^BREAKING[- ]CHANGE:", re.MULTILINE | re.IGNORECASE)

# Map commit type -> CHANGELOG section heading
_TYPE_SECTION: dict[str, str] = {
    "feat": "Added",
    "fix": "Fixed",
    "docs": "Documentation",
    "test": "Testing",
    "refactor": "Changed",
    "perf": "Performance",
    "chore": "Maintenance",
    "ci": "CI/CD",
}

_SECTION_ORDER = [
    "Added",
    "Changed",
    "Fixed",
    "Performance",
    "Documentation",
    "CI/CD",
    "Testing",
    "Maintenance",
    "Other",
]


class ParsedCommit(NamedTuple):
    sha: str
    type: str
    scope: str
    breaking: bool
    description: str
    raw_body: str

    @property
    def section(self) -> str:
        return _TYPE_SECTION.get(self.type, "Other")

    @property
    def line(self) -> str:
        scope_part = f"**{self.scope}**: " if self.scope else ""
        breaking_tag = " (BREAKING CHANGE)" if self.breaking else ""
        return f"- {scope_part}{self.description}{breaking_tag} ({self.sha[:8]})"


def _run(cmd: list[str], *, check: bool = True, capture: bool = True) -> str:
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
        cwd=ROOT,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Command {cmd!r} failed:\n{result.stderr}")
    return result.stdout.strip() if capture else ""


def _last_tag() -> str | None:
    """Return the most recent v* tag reachable from HEAD, or None."""
    try:
        tag = _run(["git", "describe", "--tags", "--match", "v*", "--abbrev=0"])
        return tag if tag else None
    except RuntimeError:
        return None


def _commits_since(ref: str | None) -> list[tuple[str, str, str]]:
    """Return list of (sha, subject, body) tuples since *ref* (or all commits)."""
    range_spec = f"{ref}..HEAD" if ref else "HEAD"
    raw = _run(["git", "log", range_spec, "--format=%H\x1f%s\x1f%b\x1e"])
    entries = []
    for block in raw.split("\x1e"):
        block = block.strip()
        if not block:
            continue
        parts = block.split("\x1f", 2)
        sha = parts[0].strip()
        subject = parts[1].strip() if len(parts) > 1 else ""
        body = parts[2].strip() if len(parts) > 2 else ""
        entries.append((sha, subject, body))
    return entries


def parse_commits(since_ref: str | None = None) -> list[ParsedCommit]:
    """Parse conventional commits since *since_ref* tag."""
    raw = _commits_since(since_ref)
    parsed: list[ParsedCommit] = []
    for sha, subject, body in raw:
        m = _CC_PATTERN.match(subject)
        if not m:
            continue
        breaking = bool(m.group("breaking")) or bool(_BREAKING_FOOTER.search(body))
        parsed.append(
            ParsedCommit(
                sha=sha,
                type=m.group("type"),
                scope=m.group("scope") or "",
                breaking=breaking,
                description=m.group("desc"),
                raw_body=body,
            )
        )
    return parsed


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


def read_version() -> tuple[int, int, int]:
    """Read version from pyproject.toml -> (major, minor, patch)."""
    text = PYPROJECT.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', text, re.MULTILINE)
    if not m:
        raise ValueError('Could not find version = "X.Y.Z" in pyproject.toml')
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def write_version(major: int, minor: int, patch: int) -> None:
    """Update version in pyproject.toml in-place."""
    text = PYPROJECT.read_text(encoding="utf-8")
    new_text = re.sub(
        r'^(version\s*=\s*")(\d+\.\d+\.\d+)(")',
        rf'\g<1>{major}.{minor}.{patch}\g<3>',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if new_text == text:
        raise ValueError("Version replacement had no effect -- check pyproject.toml format")
    PYPROJECT.write_text(new_text, encoding="utf-8")


def bump_version(
    current: tuple[int, int, int],
    bump: str,
) -> tuple[int, int, int]:
    """Return the bumped version tuple."""
    major, minor, patch = current
    if bump == "major":
        return (major + 1, 0, 0)
    if bump == "minor":
        return (major, minor + 1, 0)
    if bump == "patch":
        return (major, minor, patch + 1)
    raise ValueError(f"Unknown bump type: {bump!r}")


def infer_bump(commits: list[ParsedCommit]) -> str:
    """Infer the minimum required bump from a list of parsed commits."""
    if any(c.breaking for c in commits):
        return "major"
    if any(c.type == "feat" for c in commits):
        return "minor"
    return "patch"


# ---------------------------------------------------------------------------
# Changelog generation
# ---------------------------------------------------------------------------

_UNRELEASED_PLACEHOLDER = "## [Unreleased]\n\n<!-- Next release notes will appear here -->\n"


def generate_section(
    version: tuple[int, int, int],
    commits: list[ParsedCommit],
    today: str | None = None,
) -> str:
    """Generate a CHANGELOG section string for *version*."""
    ver_str = "{}.{}.{}".format(*version)
    when = today or datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%d")

    # Group by section
    sections: dict[str, list[str]] = {}
    for c in commits:
        sections.setdefault(c.section, []).append(c.line)

    lines = [f"## [{ver_str}] -- {when}", ""]
    for heading in _SECTION_ORDER:
        if heading in sections:
            lines.append(f"### {heading}")
            lines.extend(sections[heading])
            lines.append("")

    return "\n".join(lines)


def update_changelog(
    new_section: str,
    new_version: tuple[int, int, int],
    prev_version: tuple[int, int, int] | None,
) -> None:
    """Insert *new_section* into CHANGELOG.md and update link footer."""
    if not CHANGELOG.exists():
        raise FileNotFoundError(f"CHANGELOG.md not found at {CHANGELOG}")

    text = CHANGELOG.read_text(encoding="utf-8")

    new_ver_str = "{}.{}.{}".format(*new_version)
    prev_ver_str = "{}.{}.{}".format(*prev_version) if prev_version else "0.0.0"

    # Replace the [Unreleased] block: keep heading, reset content, insert new section
    unreleased_pattern = re.compile(
        r"^## \[Unreleased\].*?(?=^## \[|^\[Unreleased\]:|\Z)",
        re.DOTALL | re.MULTILINE,
    )

    replacement = _UNRELEASED_PLACEHOLDER + "\n---\n\n" + new_section + "\n"
    if unreleased_pattern.search(text):
        text = unreleased_pattern.sub(replacement, text, count=1)
    else:
        # No existing [Unreleased] block -- prepend
        text = replacement + "\n" + text

    # Update link footer
    unreleased_link = (
        f"[Unreleased]: https://github.com/manus-use/manus-use/compare/v{new_ver_str}...HEAD"
    )
    new_ver_link = (
        f"[{new_ver_str}]: https://github.com/manus-use/manus-use/compare/v{prev_ver_str}...v{new_ver_str}"
    )

    text = re.sub(
        r"^\[Unreleased\]:.*$",
        unreleased_link,
        text,
        flags=re.MULTILINE,
    )

    if f"[{new_ver_str}]:" not in text:
        text = text.replace(
            unreleased_link,
            unreleased_link + "\n" + new_ver_link,
        )

    CHANGELOG.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def cmd_version(_args: argparse.Namespace) -> int:
    """Print current version."""
    v = read_version()
    print("{}.{}.{}".format(*v))
    return 0


def cmd_notes(_args: argparse.Namespace) -> int:
    """Generate and print release notes from recent commits."""
    last_tag = _last_tag()
    if last_tag:
        print(f"Commits since {last_tag}:", file=sys.stderr)
    else:
        print("No previous tags found -- using all commits", file=sys.stderr)

    commits = parse_commits(last_tag)
    if not commits:
        print("No conventional commits found since last tag.", file=sys.stderr)
        return 0

    current = read_version()
    inferred = infer_bump(commits)
    next_ver = bump_version(current, inferred)

    section = generate_section(next_ver, commits)
    print(section)
    print(
        f"\nInferred bump: {inferred} -> {next_ver[0]}.{next_ver[1]}.{next_ver[2]}",
        file=sys.stderr,
    )
    return 0


def cmd_bump(args: argparse.Namespace) -> int:  # noqa: C901
    """Bump version, update CHANGELOG, commit, and tag."""
    dry_run: bool = args.dry_run
    bump_type: str = args.bump_type

    last_tag = _last_tag()
    commits = parse_commits(last_tag)

    if not commits and not getattr(args, "force", False):
        print(
            "No conventional commits found since last tag. "
            "Use --force to release anyway.",
            file=sys.stderr,
        )
        return 1

    current = read_version()

    if bump_type == "auto":
        bump_type = infer_bump(commits) if commits else "patch"

    next_ver = bump_version(current, bump_type)
    ver_str = "{}.{}.{}".format(*next_ver)
    tag = f"v{ver_str}"

    print(f"Current version : {current[0]}.{current[1]}.{current[2]}")
    print(f"Bump type       : {bump_type}")
    print(f"Next version    : {ver_str}")
    print(f"Tag             : {tag}")
    print(f"Commits included: {len(commits)}")
    print()

    section = generate_section(next_ver, commits)
    print("Generated changelog section:")
    print("-" * 60)
    print(section)
    print("-" * 60)

    if dry_run:
        print("\n[dry-run] No files modified.")
        return 0

    # 1. Bump pyproject.toml
    write_version(*next_ver)
    print(f"Updated pyproject.toml -> {ver_str}")

    # 2. Update CHANGELOG.md
    update_changelog(section, next_ver, current)
    print("Updated CHANGELOG.md")

    # 3. Commit
    _run(["git", "add", str(PYPROJECT), str(CHANGELOG)])
    _run(["git", "commit", "-m", f"chore(release): bump version to {ver_str}"])
    print("Committed version bump")

    # 4. Tag
    _run(["git", "tag", "-a", tag, "-m", f"Release {ver_str}"])
    print(f"Tagged {tag}")

    if getattr(args, "push", False):
        _run(["git", "push", "origin", "HEAD"])
        _run(["git", "push", "origin", tag])
        print("Pushed commits and tag -- CI will publish to PyPI")
    else:
        print(f"\nPush when ready:\n  git push origin HEAD && git push origin {tag}")

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python scripts/release.py",
        description="manus-use release helper -- bump version, update CHANGELOG, tag.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scripts/release.py notes          # preview release notes\n"
            "  python scripts/release.py patch --dry-run\n"
            "  python scripts/release.py minor --push\n"
            "  python scripts/release.py auto           # infer bump from commits\n"
        ),
    )
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("version", help="Print current version and exit")
    sub.add_parser("notes", help="Generate release notes from recent commits (read-only)")

    for name in ("patch", "minor", "major", "auto"):
        bp = sub.add_parser(name, help=f"Bump {name} version")
        bp.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview changes without writing files",
        )
        bp.add_argument(
            "--push",
            action="store_true",
            help="Push commits and tag to origin after bumping",
        )
        bp.add_argument(
            "--force",
            action="store_true",
            help="Release even when no conventional commits found",
        )
        bp.set_defaults(bump_type=name)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        return cmd_version(args)
    if args.command == "notes":
        return cmd_notes(args)
    if args.command in ("patch", "minor", "major", "auto"):
        return cmd_bump(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
