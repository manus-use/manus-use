#!/usr/bin/env python3
"""Backwards-compat shim — delegates to va_agent.py.

``python vi_agent.py CVE-...`` is equivalent to ``python va_agent.py CVE-...``.
This file exists only so existing scripts that reference vi_agent.py keep working.
"""
import runpy, sys  # noqa: E401
sys.argv[0] = "va_agent.py"
runpy.run_path(__file__.replace("vi_agent.py", "va_agent.py"), run_name="__main__")
