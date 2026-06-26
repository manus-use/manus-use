"""Vulnerability Discovery agent.

This module provides :class:`VulnerabilityDiscoveryAgent`, a Strands-based
agent that performs parallel CVE discovery with EPSS filtering using
configurable 2-week time slices.

The agent orchestrates a multi-step workflow:

1. A *master* agent calculates weekly time-slices for the requested date
   window.
2. A *capture* tool spawns one sub-agent per time-slice in a thread pool,
   each sub-agent uses ``obtain_cves`` (EPSS-filtered) and ``submit_cves``
   to fetch and record newly-published CVEs.
3. The master agent validates that all time-slices produced successful
   submissions and returns a structured summary.

The module is written so it can be *imported* without the optional heavy
dependencies (``strands``, ``strands_tools``, ``boto3``) being installed:
all such imports are deferred into :meth:`VulnerabilityDiscoveryAgent.__init__`
and guarded with ``try/except ImportError``. Only constructing the agent
requires those dependencies.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field

from manus_use.config import Config

__all__ = ["VulnerabilityDiscoveryAgent", "Submission", "DEFAULT_MODEL_ID"]

# Sensible default used only when no model can be resolved from ``Config``.
DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-4-20250514-v1:0"

# Default EPSS score threshold: only CVEs with EPSS >= this value are kept.
DEFAULT_MIN_EPSS: float = 0.5

# Default discovery window: look back this many days when no --since is given.
DEFAULT_LOOKBACK_DAYS: int = 28  # ~4 weeks


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class Submission(BaseModel):
    """Structured summary of one time-slice CVE capture run."""

    total: int = Field(description="Total number of CVEs found")
    total_with_high_epss: int = Field(description="Total number of CVEs with high EPSS")
    total_submitted: int = Field(description="Total number of CVEs submitted")
    error: str | None = Field(default=None, description="Error message if any error occurred")


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

_CAPTURE_SYSTEM_PROMPT = """\
You are a cybersecurity intelligence expert to discover and submit vulnerabilities \
using the `obtain_cves` and `submit_cves` tools.

**IMPORTANT**
- First use obtain_cves to find CVEs; after obtaining CVEs, immediately submit \
  them using submit_cves.
- The obtain_cves tool already filters for high EPSS scores.
- Submit CVEs in batches through submit_cves, with a maximum of 10 CVEs per \
  submission.
- Make sure all CVEs are submitted.
"""

_MASTER_SYSTEM_PROMPT = """\
You are a master control agent. Your job is to calculate date ranges by week to \
discover and submit vulnerabilities using the `capture_cves` tool.

**Steps:**
1. FIRST: Use python_repl and current_time to calculate time slices for the \
   requested date window, each time slice spanning one week with a start_date \
   and end_date. Store these exact dates, e.g. \
   {{'start_date': '2025-07-21', 'end_date': '2025-07-27'}}.
2. THEN: Capture CVEs with the following tasks using the EXACT time slices from \
   step 1:
   - Task 1: Capture CVEs for EXACT time slices — pass the list of time slices \
     (each with start_date and end_date) to the `capture_cves` tool.
   - Task 2: Check the results from Task 1 to confirm that all submissions for \
     each time slice were successful.

IMPORTANT:
- Calculate the time slices in STEP 1 BEFORE calling `capture_cves`.
- Validate all submissions through the results returned by `capture_cves`.
"""


# ---------------------------------------------------------------------------
# VulnerabilityDiscoveryAgent
# ---------------------------------------------------------------------------


class VulnerabilityDiscoveryAgent:
    """Agent that orchestrates a parallel vulnerability-discovery workflow.

    The agent wires together the ``obtain_cves`` and ``submit_cves`` tools
    bundled with ManusUse and drives them with a two-level multi-agent
    architecture: a master scheduler that splits the requested time window into
    weekly slices and dispatches each slice to a thread-pool worker agent.

    Parameters
    ----------
    config:
        ManusUse configuration. Loaded from disk when omitted.
    model:
        A pre-built Strands model instance. Takes precedence over ``model_name``
        and the model resolved from ``config``.
    model_name:
        Explicit model id to use instead of resolving one from ``config``. Falls
        back to :data:`DEFAULT_MODEL_ID`.

    Raises
    ------
    ImportError
        If the optional ``strands`` / ``strands_tools`` dependencies required to
        run the agent are not installed.
    """

    def __init__(
        self,
        config: Config | None = None,
        *,
        model: Any | None = None,
        model_name: str | None = None,
    ) -> None:
        self.config = config or Config.from_file()

        try:
            os.environ.setdefault("BYPASS_TOOL_CONSENT", "True")

            from strands import Agent, tool  # noqa: F401 – imported for closure
            from strands_tools import current_time

            import manus_use.tools.obtain_cves as _obtain_cves_mod
            import manus_use.tools.submit_cves as _submit_cves_mod
            from manus_use.tools.python_repl import python_repl
        except ImportError as exc:  # pragma: no cover - depends on env
            raise ImportError(
                "VulnerabilityDiscoveryAgent requires the optional 'strands' "
                "and 'strands_tools' dependencies. Install them to run discovery."
            ) from exc

        model_obj = model if model is not None else self._resolve_model(model_name)

        # Build the capture_cves tool as a closure so it can reference
        # model_obj and the imported modules without module-level state.
        capture_cves_tool = self._build_capture_cves_tool(
            model_obj=model_obj,
            obtain_cves_mod=_obtain_cves_mod,
            submit_cves_mod=_submit_cves_mod,
        )

        from strands import Agent as _Agent

        self.agent = _Agent(
            model=model_obj,
            system_prompt=_MASTER_SYSTEM_PROMPT,
            tools=[
                python_repl,
                current_time,
                capture_cves_tool,
            ],
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_model(self, model_name: str | None) -> Any:
        """Resolve a model instance from an explicit name or from config."""
        if model_name:
            return model_name

        try:
            return self.config.get_model()
        except Exception:
            return DEFAULT_MODEL_ID

    @staticmethod
    def _build_capture_cves_tool(
        *,
        model_obj: Any,
        obtain_cves_mod: Any,
        submit_cves_mod: Any,
    ):
        """Return a ``@tool``-decorated function that runs parallel slice agents.

        We build this dynamically so the closure captures the resolved model
        and tool modules rather than hard-coding them at module import time.
        """
        from strands import Agent as _Agent
        from strands import tool as _tool

        @_tool
        def capture_cves(time_slices: list) -> list:
            """Obtain and submit CVEs based on specific time slices.

            Args:
                time_slices: A list of time slices where each item is a dict
                    containing 'start_date' and 'end_date', e.g.
                    {'start_date': '2025-07-21', 'end_date': '2025-07-27'}.

            Returns:
                A list of submission summary strings, one per time slice.
            """
            import concurrent.futures

            # Sort newest-first for faster feedback on recent CVEs.
            slices = list(time_slices)
            if slices and "end_date" in slices[0]:
                slices = sorted(slices, key=lambda x: x["end_date"], reverse=True)

            # Cap at 4 slices per run to avoid runaway parallelism.
            slices = slices[:4]

            def process_time_slice(time_slice):
                print(f"[capture_cves] Processing slice: {time_slice}")
                agent = _Agent(
                    model=model_obj,
                    system_prompt=_CAPTURE_SYSTEM_PROMPT,
                    tools=[obtain_cves_mod, submit_cves_mod],
                )
                result = agent(f"Please obtain and submit CVEs in the time slice: {time_slice}")
                print(f"[capture_cves] Slice agent result: {result}")

                summary: Submission = agent.structured_output(
                    output_model=Submission,
                    prompt=(
                        "Based on our conversation, provide a summary of the CVE "
                        "submission results including total CVEs obtained, total with "
                        "high EPSS, and total submitted."
                    ),
                )
                line = f"For the {time_slice} time slice, Submission Summary: {summary}"
                print(line)
                return line

            max_workers = min(32, (os.cpu_count() or 1) + 4)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(process_time_slice, ts) for ts in slices]
                results: list[str] = []
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
            return results

        return capture_cves

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def build_request(
        *,
        since: str | None = None,
        min_epss: float = DEFAULT_MIN_EPSS,
        dry_run: bool = False,
    ) -> str:
        """Build the natural-language discovery request.

        Parameters
        ----------
        since:
            ISO-format start date for the discovery window (e.g. ``"2025-06-01"``).
            Defaults to :data:`DEFAULT_LOOKBACK_DAYS` days before today.
        min_epss:
            Minimum EPSS score threshold. CVEs below this value are ignored.
        dry_run:
            When ``True``, instruct the agent to discover but **not** submit.
        """
        if since is None:
            start = datetime.now(tz=timezone.utc) - timedelta(days=DEFAULT_LOOKBACK_DAYS)
            since = start.strftime("%Y-%m-%d")

        action = (
            "Discover CVEs but DO NOT submit them (dry-run mode)."
            if dry_run
            else "Discover and submit all high-EPSS CVEs found."
        )

        return (
            f"Please define and execute the vulnerability discovery workflow.\n"
            f"Discovery window start date: {since}\n"
            f"Minimum EPSS threshold: {min_epss}\n"
            f"{action}"
        )

    def handle_request(self, request: str) -> str:
        """Invoke the master agent and return its response as a string."""
        print("INFO: VulnerabilityDiscoveryAgent received request. Executing workflow…")
        return str(self.agent(request))

    def discover(
        self,
        *,
        since: str | None = None,
        min_epss: float = DEFAULT_MIN_EPSS,
        dry_run: bool = False,
    ) -> str:
        """Convenience wrapper: build the request and run the workflow."""
        return self.handle_request(self.build_request(since=since, min_epss=min_epss, dry_run=dry_run))
