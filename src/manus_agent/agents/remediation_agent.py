"""Remediation Agent.

This module provides :class:`RemediationAgent`, a Strands-based agent that
generates actionable, patch-ready remediation guidance for a given CVE by
querying NVD, GitHub advisories, CISA KEV, and CWE weakness databases, then
synthesising concrete mitigation steps tailored to the severity and exploitability
of the vulnerability.

The module is written so it can be *imported* without the optional heavy
dependencies (``strands``, ``strands_tools``, ``boto3``) being installed: all
such imports are deferred into :meth:`RemediationAgent.__init__` and guarded
with ``try/except ImportError``. Only constructing the agent requires those
dependencies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from manus_agent.config import Config

__all__ = ["RemediationAgent", "DEFAULT_MODEL_ID"]

# Sensible default used only when no model can be resolved from ``Config``.
DEFAULT_MODEL_ID = "us.anthropic.claude-sonnet-4-20250514-v1:0"

# Repository root (…/manus-agent) — used to locate bundled skills.
_REPO_ROOT = Path(__file__).resolve().parents[3]

_SYSTEM_PROMPT = """
You are an expert security engineer specialising in vulnerability remediation.
Given a CVE identifier you will:

1. **Gather vulnerability data** — call `get_nvd_data` to retrieve the official
   description, CVSS score, affected versions, and CWE.
2. **Check active exploitation** — call `check_cisa_kev` to determine whether
   the vulnerability is being actively exploited in the wild.
3. **Understand the weakness** — use `get_cwe_details` with the CWE ID from NVD
   to understand the root-cause software weakness.
4. **Find available fixes** — search for official patches, vendor advisories, and
   workarounds using `web_search` (query: "<product> <CVE-ID> patch fix advisory").
5. **Synthesise remediation guidance** — write a concise, actionable remediation
   report structured as follows:

   ### Summary
   One-paragraph description of the vulnerability, affected components, and
   severity (include CVSS score and vector).

   ### Exploitation Status
   Whether the CVE is on CISA KEV (actively exploited) or has public PoCs.
   State urgency level: CRITICAL / HIGH / MEDIUM / LOW.

   ### Remediation Steps
   Ordered list of concrete technical steps. Each step must:
   - Start with an action verb (Upgrade, Apply, Disable, Restrict, …)
   - Name the exact component, version, config key, or file path
   - Be achievable by a developer or system administrator
   Examples:
   * Upgrade `package-name` to >= X.Y.Z (patch released YYYY-MM-DD)
   * Set `config.option = false` in `/etc/app/config.yaml`
   * Apply vendor advisory patch from <URL>
   * If upgrade is not possible, disable feature X as a temporary workaround

   ### Verification
   How to confirm the fix has been applied (version check, config audit command,
   or automated scanner).

   ### References
   Bullet list of all source URLs used (NVD, CISA, vendor advisories, patches).

**Rules:**
- Be specific — generic advice ("keep software up to date") is not acceptable.
- If CVSS score is >= 9.0 or CVE is in CISA KEV, mark urgency as CRITICAL.
- Do not recommend actions you cannot verify with the data gathered.
- Keep the report under 800 words; brevity is a feature.
"""


class RemediationAgent:
    """Strands-based agent that produces remediation guidance for a CVE.

    Parameters
    ----------
    config:
        :class:`~manus_agent.config.Config` instance. When *None* the default
        config file search is performed via :meth:`Config.from_file`.

    Example
    -------
    >>> agent = RemediationAgent()
    >>> report = agent.remediate("CVE-2024-3094")
    >>> print(report)
    """

    def __init__(self, *, config: Config | None = None) -> None:
        try:
            from strands import Agent
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "strands-agents is required for RemediationAgent. Install it with: pip install strands-agents"
            ) from exc

        self.config = config or Config.from_file()
        model = self.config.get_model()

        # Collect tools — all optional; agent degrades gracefully if unavailable.
        tools: list[Any] = []
        try:
            from manus_agent.tools.get_nvd_data import get_nvd_data

            tools.append(get_nvd_data)
        except ImportError:
            pass

        try:
            from manus_agent.tools.check_cisa_kev import check_cisa_kev

            tools.append(check_cisa_kev)
        except ImportError:
            pass

        try:
            from manus_agent.tools.get_cwe_details import get_cwe_details

            tools.append(get_cwe_details)
        except ImportError:
            pass

        try:
            from manus_agent.tools.web_search import web_search

            tools.append(web_search)
        except ImportError:
            pass

        try:
            from manus_agent.tools.http_request import http_request

            tools.append(http_request)
        except ImportError:
            pass

        # Context management — use agentic mode when the SDK supports it.
        context_manager = getattr(self.config, "agent", None)
        context_manager_val = (
            getattr(context_manager, "context_manager", "agentic") if context_manager is not None else "agentic"
        )

        agent_kwargs: dict[str, Any] = {
            "model": model,
            "tools": tools,
            "system_prompt": _SYSTEM_PROMPT,
        }
        try:
            agent_kwargs["context_manager"] = context_manager_val
        except Exception:
            pass

        self.agent: Any = Agent(**agent_kwargs)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def build_request(cve_id: str, *, output: str = "text") -> str:
        """Return the prompt string sent to the agent.

        Parameters
        ----------
        cve_id:
            CVE identifier (e.g. ``"CVE-2024-3094"``).
        output:
            Desired output format (``"text"`` or ``"json"``). For *json* the
            agent is instructed to wrap the report fields in a JSON envelope.
        """
        cve_id = cve_id.strip().upper()
        prompt = f"Generate a complete remediation report for {cve_id}."
        if output == "json":
            prompt += (
                " Return the report as a JSON object with these keys: "
                "cve, summary, exploitation_status, urgency, "
                "remediation_steps (list of strings), verification, references (list of URLs)."
            )
        return prompt

    def handle_request(self, request: str) -> str:
        """Invoke the agent and return its response as a string."""
        return str(self.agent(request))

    def remediate(self, cve_id: str, *, output: str = "text") -> str:
        """Convenience wrapper: build the request and run the workflow.

        Parameters
        ----------
        cve_id:
            CVE identifier.
        output:
            ``"text"`` (default) or ``"json"``.
        """
        return self.handle_request(self.build_request(cve_id, output=output))


# ---------------------------------------------------------------------------
# Thin backwards-compatible entry point (mirrors root remediation_agent.py)
# ---------------------------------------------------------------------------


def _main() -> None:
    """CLI entry-point kept for backwards compatibility.

    Prefer ``manus-agent remediate <CVE-ID>`` instead.
    """
    import sys

    cve_id = sys.argv[1] if len(sys.argv) > 1 else "CVE-2024-3094"
    agent = RemediationAgent()
    print("=== Remediation Agent ===")
    print(f"CVE: {cve_id}\n")
    print(agent.remediate(cve_id))


if __name__ == "__main__":
    _main()
