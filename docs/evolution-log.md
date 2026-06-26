# Evolution Log

## 2026-06-24 — chore: ruff lint cleanup

Ran full ruff lint pass (`E`, `F`, `I`, `N`, `W`, `B`, `UP` rules, target Python 3.10).

**Before:** 1137 violations across the codebase  
**After:** 0 violations

### Changes

- **Auto-fixed (956 issues):** import sorting (`I`), blank-line style (`E3xx`), whitespace (`W`), deprecated typing constructs (`UP`), and other auto-correctable issues.

- **Manual fixes (181 issues):**
  - Stripped trailing whitespace throughout all `.py` files
  - `analyze_browser_use_simple.py`: extracted default string variable to avoid backslash in f-string expression (Python 3.12+ syntax)
  - `src/manus_use/agents/browser.py`: added `# noqa: E402` for intentional mid-file imports after `sys.path` setup
  - `src/manus_use/cli_enhanced.py`, `cli_v2.py`: bare `except:` → `except Exception:` (E722); removed unused `HorizontalGroup`/`Link` imports (F401)
  - `src/manus_use/multi_agents/__init__.py`: removed deprecated `Dict`, `List`, `Optional` typing imports (UP035/F401)
  - `src/manus_use/sandbox/docker_sandbox.py`: bare `except:` → `except Exception:` (E722); fixed corrupted return+def line
  - `src/manus_use/tools/__init__.py`: removed unused `List`, `Optional`, `strands_tools.retrieve` imports (UP/F401)
  - `src/manus_use/tools/browser_utils.py`: `raise BrowserTimeoutError(...)` → `raise ... from None` (B904)
  - `src/manus_use/tools/file_operations.py`: added `from e` to 4 `RuntimeError` raises in except blocks (B904)
  - `src/manus_use/tools/python_repl.py`: removed redefined imports (F811)
  - `src/manus_use/tools/search_exploit_db.py`, `search_packetstorm.py`: expanded inline `if ...: continue` statements (E701)
  - `src/manus_use/tools/web_search.py`: replaced unused `DDGS` import with package-existence check; added `from None` to `raise ImportError` (B904/F401)
  - `tests/test_agents.py`: added `# noqa: E402` for mid-file section imports; renamed `MockChatOpenAI`/`MockChatBedrock`/etc. parameters to lowercase (N803)
  - `vd_agent.py`, `workflow_agent.py`: added `# noqa: E402` for post-`sys.path` imports
  - `workflow_test.py`: replaced undefined `manus_workflow_module.manus_workflow()` with direct `manus_workflow()` call (F821)

- **Formatting:** `ruff format` applied to 68 files for consistent code style
