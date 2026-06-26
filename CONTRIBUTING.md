# Contributing to ManusUse

Thank you for your interest in contributing! This guide covers everything you need to make a clean, mergeable PR.

## Table of Contents

- [Development setup](#development-setup)
- [Running tests](#running-tests)
- [Linting and formatting](#linting-and-formatting)
- [Project layout](#project-layout)
- [PR conventions](#pr-conventions)
- [Adding a new agent](#adding-a-new-agent)
- [Adding a new CLI subcommand](#adding-a-new-cli-subcommand)

---

## Development setup

```bash
git clone https://github.com/manus-use/manus-use.git
cd manus-use

# Install the package in editable mode with all dev/test extras
pip install -e ".[dev,browser,search,visualization]"
```

If you are working inside a git **worktree** (e.g. for a parallel feature branch), make sure you install from the worktree directory, not the main clone:

```bash
git -C /path/to/manus-use worktree add /tmp/my-feature -b feat/my-feature origin/main
cd /tmp/my-feature
pip install -e ".[dev]"
```

---

## Running tests

```bash
# All unit tests (integration tests excluded by default)
pytest tests/ -v

# With coverage
pytest tests/ --cov=manus_use --cov-report=html

# Run a specific test file
pytest tests/test_cli.py -v

# Run a specific test by name
pytest tests/test_config.py::test_default_config -v

# Include integration tests (requires live services)
pytest tests/ -v -m "integration"
```

The `pytest.ini_options` in `pyproject.toml` excludes `@pytest.mark.integration` tests by default. Integration tests require live API keys and network access.

---

## Linting and formatting

We use [ruff](https://docs.astral.sh/ruff/) for both linting and formatting.

```bash
# Check for lint violations
ruff check src/ tests/

# Auto-fix fixable violations
ruff check src/ tests/ --fix

# Format code
ruff format src/ tests/

# Check formatting without changing files
ruff format --check src/ tests/
```

CI will fail if `ruff check` or `ruff format --check` reports any issues. Always run both before opening a PR.

Alternatively, use [hatch](https://hatch.pypa.io/):

```bash
hatch run lint      # ruff check
hatch run format    # ruff format
hatch run test      # pytest
hatch run test-cov  # pytest --cov
```

---

## Project layout

```
manus-use/
├── src/manus_use/
│   ├── agents/          # Agent classes (one file per agent type)
│   │   ├── base.py      # BaseManusAgent — all agents inherit from here
│   │   ├── manus.py     # ManusAgent (general-purpose)
│   │   ├── vi_agent.py  # VulnerabilityIntelligenceAgent
│   │   └── ...
│   ├── multi_agents/    # WorkflowAgent + Orchestrator
│   ├── tools/           # @tool-decorated functions used by agents
│   ├── sandbox/         # Docker sandbox helpers
│   ├── cli.py           # manus-use CLI entry point
│   └── config.py        # Config model (Pydantic + TOML)
├── tests/               # pytest test suite
├── config/
│   └── config.example.toml
├── examples/            # Runnable demos
└── pyproject.toml
```

**Key conventions:**

- Each agent class lives in its own file under `src/manus_use/agents/`.
- All agents inherit from `BaseManusAgent` (`agents/base.py`), which inherits from `strands.Agent`.
- Tools are `@strands.tools.tool`-decorated functions. Import them as `from manus_use.tools.my_tool import my_tool`.
- Use `from manus_use.config import Config` — **never** `from src.manus_use.config import Config`.
- Defer heavy imports (MCP, Docker, Playwright) to function bodies so the package is always importable.

---

## PR conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

feat(cli): add --dry-run flag to manus-use discover
fix(config): respect aws_region from [agent] section
docs(readme): add Ollama provider example
test(vi_agent): cover goal-loop completeness check
refactor(agents): extract _build_agent helper to base class
chore(deps): bump strands-agents to >=1.45.0
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`

**PR checklist:**

- [ ] `ruff check src/ tests/` — zero violations
- [ ] `ruff format --check src/ tests/` — no formatting changes needed
- [ ] `pytest tests/ -v` — all tests pass (integration tests excluded)
- [ ] New behaviour is covered by tests
- [ ] No `from src.manus_use.` imports (use `from manus_use.` — these break installed packages)
- [ ] No `sys.path.insert` calls in `src/` (breaks installed packages)
- [ ] Heavy optional deps deferred to function scope, not module top-level

---

## Adding a new agent

1. Create `src/manus_use/agents/my_agent.py`:

```python
"""MyAgent — short description."""

from manus_use.agents.base import BaseManusAgent
from manus_use.config import Config

DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-4-20250514-v1:0"
DEFAULT_AWS_REGION = "us-east-1"


class MyAgent(BaseManusAgent):
    """One-line description."""

    def __init__(self, config: Config | None = None, **kwargs):
        config = config or Config.from_file()
        super().__init__(
            config=config,
            tools=[...],
            system_prompt=self._system_prompt(),
            **kwargs,
        )

    @staticmethod
    def build_request(param: str) -> str:
        """Build a natural-language request string for handle_request."""
        return f"Do something with {param}."

    def handle_request(self, request: str) -> str:
        """Run the agent and return a result string."""
        result = self(request)
        return str(result)

    def _system_prompt(self) -> str:
        return "You are a helpful agent that does X."
```

2. Export it from `src/manus_use/agents/__init__.py`.

3. Write tests in `tests/test_my_agent.py` — mock `strands.Agent.__init__` and `strands.Agent.__call__` so tests don't need live credentials.

---

## Adding a new CLI subcommand

Follow the pattern of existing subcommands (`analyze`, `discover`, `remediate`):

1. Add `_build_mycommand_parser()` and `_run_mycommand()` to `src/manus_use/cli.py`.
2. Register the subcommand name in the `_SUBCOMMANDS` set.
3. Add a dispatch block in `main()`.
4. Update the `epilog` string in `_build_run_parser()` with a usage example.
5. Add tests in `tests/test_readme_cli.py` (or a dedicated test file) that verify:
   - The help text exits 0.
   - The subcommand is registered in `_SUBCOMMANDS`.
   - `main()` routes to your runner function.

---

## Questions?

Open a [GitHub Discussion](https://github.com/manus-use/manus-use/discussions) or file an [issue](https://github.com/manus-use/manus-use/issues).
