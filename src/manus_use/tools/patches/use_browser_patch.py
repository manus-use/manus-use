"""Compatibility patch for ``strands_tools.use_browser`` actions.

This patch focuses on three general browser execution issues:
1. Safely propagating optional timeout arguments only to compatible actions.
2. Normalizing ``evaluate`` scripts into valid Playwright callables.
3. Rebinding stale action registrations so patched methods are actually invoked.
"""

import asyncio
import inspect
import logging
import os
from typing import Any, Callable, Dict, Optional

from manus_use.tools.browser_utils import (
    BrowserTimeoutError,
    get_html_with_fallback,
    get_text_with_fallback,
    is_selector_syntax_error,
    normalize_browser_selector,
    prepare_evaluate_script,
)

logger = logging.getLogger(__name__)

_PATCH_CONFIG: Dict[str, Any] = {
    "default_timeout_ms": int(os.getenv("STRANDS_BROWSER_DEFAULT_TIMEOUT", "10000")),
    "max_retries": int(os.getenv("STRANDS_BROWSER_MAX_RETRIES", "3")),
    "retry_delay_seconds": int(os.getenv("STRANDS_BROWSER_RETRY_DELAY", "2")),
    "enable_fallbacks": os.getenv("STRANDS_BROWSER_ENABLE_FALLBACKS", "true").lower() == "true",
}
_PATCH_STATE: Dict[str, Any] = {
    "applied": False,
    "original_init": None,
    "original_handle_action": None,
}


def _coerce_int(value: Any, fallback: int) -> int:
    """Convert a runtime value into a positive integer fallbacking safely."""
    try:
        if value is None:
            raise ValueError("missing")
        coerced = int(value)
        return coerced if coerced > 0 else fallback
    except (TypeError, ValueError):
        return fallback


def configure_browser_patch(
    *,
    default_timeout_ms: Optional[int] = None,
    max_retries: Optional[int] = None,
    retry_delay_seconds: Optional[int] = None,
    enable_fallbacks: Optional[bool] = None,
) -> Dict[str, Any]:
    """Update runtime patch configuration and return the active settings."""
    if default_timeout_ms is not None:
        _PATCH_CONFIG["default_timeout_ms"] = _coerce_int(
            default_timeout_ms, _PATCH_CONFIG["default_timeout_ms"]
        )
    if max_retries is not None:
        _PATCH_CONFIG["max_retries"] = _coerce_int(max_retries, _PATCH_CONFIG["max_retries"])
    if retry_delay_seconds is not None:
        _PATCH_CONFIG["retry_delay_seconds"] = _coerce_int(
            retry_delay_seconds, _PATCH_CONFIG["retry_delay_seconds"]
        )
    if enable_fallbacks is not None:
        _PATCH_CONFIG["enable_fallbacks"] = bool(enable_fallbacks)
    return dict(_PATCH_CONFIG)


def _get_timeout_ms(args: Dict[str, Any]) -> int:
    return _coerce_int(args.get("timeout_ms"), _PATCH_CONFIG["default_timeout_ms"])


def _format_action_result(result: Any):
    return [{"text": str(result)}]


def _is_non_retryable_error(error: Exception) -> bool:
    if is_selector_syntax_error(error):
        return True

    text = str(error).lower()
    return any(
        marker in text
        for marker in [
            "could not resolve domain",
            "connection refused",
            "ssl/tls error",
            "certificate error",
            "protocol error (page.navigate): cannot navigate to invalid url",
        ]
    )


def _rebind_action_registry(browser_manager: Any, browser_api_methods: Any) -> None:
    """Refresh manager action registrations so patched callables are used."""
    actions = getattr(browser_manager, "_actions", None)
    if not isinstance(actions, dict):
        return

    for action_name in ("get_text", "get_html"):
        patched_action = getattr(browser_api_methods, action_name, None)
        if callable(patched_action):
            actions[action_name] = patched_action


def _resolve_action_method(browser_manager: Any, browser_api_methods: Any, action: str) -> Optional[Callable[..., Any]]:
    _rebind_action_registry(browser_manager, browser_api_methods)

    actions = getattr(browser_manager, "_actions", None)
    if isinstance(actions, dict) and action in actions:
        return actions[action]

    direct_method = getattr(browser_api_methods, action, None)
    if callable(direct_method):
        return direct_method
    return None


def _build_action_args(action_method: Callable[..., Any], args: Dict[str, Any], page: Any, browser_manager: Any) -> Dict[str, Any]:
    signature = inspect.signature(action_method)
    action_args = {name: value for name, value in args.items() if name in signature.parameters}

    if "page" in signature.parameters:
        action_args["page"] = page
    if "browser_manager" in signature.parameters:
        action_args["browser_manager"] = browser_manager
    if "timeout_ms" in signature.parameters:
        action_args["timeout_ms"] = _get_timeout_ms(args)
    if "script" in signature.parameters and isinstance(action_args.get("script"), str):
        action_args["script"] = prepare_evaluate_script(action_args["script"])
    if "selector" in signature.parameters and isinstance(action_args.get("selector"), str):
        action_args["selector"] = normalize_browser_selector(action_args["selector"])

    return action_args


def _missing_required_params(action_method: Callable[..., Any], action_args: Dict[str, Any]) -> list[str]:
    signature = inspect.signature(action_method)
    missing = []
    for name, param in signature.parameters.items():
        if param.default != inspect.Parameter.empty:
            continue
        if name in {"page", "browser_manager"}:
            continue
        if name not in action_args:
            missing.append(name)
    return missing


def apply_comprehensive_patch(
    *,
    default_timeout_ms: Optional[int] = None,
    max_retries: Optional[int] = None,
    retry_delay_seconds: Optional[int] = None,
    enable_fallbacks: Optional[bool] = None,
) -> bool:
    """Apply a compatibility patch to ``strands_tools.use_browser`` if available."""
    configure_browser_patch(
        default_timeout_ms=default_timeout_ms,
        max_retries=max_retries,
        retry_delay_seconds=retry_delay_seconds,
        enable_fallbacks=enable_fallbacks,
    )

    try:
        from strands_tools.use_browser import BrowserApiMethods, BrowserManager
    except ImportError as exc:
        logger.warning("Could not patch use_browser (not installed): %s", exc)
        return False

    async def patched_get_text(page, selector, timeout_ms=None):
        """Patched get_text with fallback-aware timeout handling."""
        timeout_ms = _coerce_int(timeout_ms, _PATCH_CONFIG["default_timeout_ms"])

        try:
            text, actual_selector = await get_text_with_fallback(
                page,
                selector,
                timeout_ms=timeout_ms,
                use_fallbacks=_PATCH_CONFIG["enable_fallbacks"],
            )
            if actual_selector and actual_selector != selector:
                logger.info(
                    "Used fallback selector '%s' instead of '%s'",
                    actual_selector,
                    selector,
                )
                return f"Text content (fallback '{actual_selector}'): {text}"
            return f"Text content: {text}"
        except BrowserTimeoutError as error:
            raise ValueError(
                f"Element '{selector}' not found after {timeout_ms}ms. "
                f"Tried fallbacks: {error.tried_fallbacks}. "
                "Suggestions:\n"
                "  1. Use get_html() to inspect page structure\n"
                "  2. Use evaluate() to find available elements\n"
                "  3. Check if page is fully loaded"
            ) from error

    async def patched_get_html(page, selector=None, timeout_ms=None):
        """Patched get_html with compatibility-safe timeout handling."""
        timeout_ms = _coerce_int(timeout_ms, _PATCH_CONFIG["default_timeout_ms"])
        try:
            result = await get_html_with_fallback(page, selector=selector, timeout_ms=timeout_ms)
        except BrowserTimeoutError as error:
            # get_html is often used as an exploratory/inspection step. If a caller provided
            # an overly-specific selector (common across different Git/web UIs), failing hard
            # prevents inspection entirely. Fall back to the full page HTML so the caller/LLM
            # can adjust selectors using the returned DOM.
            logger.warning(
                "get_html timed out waiting for selector '%s' after %sms on %s; returning full page content",
                selector,
                timeout_ms,
                getattr(error, "url", None) or "(unknown url)",
            )
            result = await page.content()
        return result[:1000] + "..." if len(result) > 1000 else result

    original_init = _PATCH_STATE.get("original_init") or BrowserManager.__init__
    _PATCH_STATE["original_init"] = original_init
    _PATCH_STATE["original_handle_action"] = getattr(
        BrowserManager,
        "handle_action",
        _PATCH_STATE.get("original_handle_action"),
    )

    def patched_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        _rebind_action_registry(self, BrowserApiMethods)

    async def patched_handle_action(self, action, **kwargs):
        args = dict(kwargs.get("args") or {})
        max_retries_local = _PATCH_CONFIG["max_retries"]
        retry_delay_local = _PATCH_CONFIG["retry_delay_seconds"]

        async def execute_action():
            action_method = _resolve_action_method(self, BrowserApiMethods, action)
            if action_method is None:
                return [{"text": f"Error: Unknown action {action}"}]

            page, _ = await self.ensure_browser(args.get("launchOptions"))
            action_args = _build_action_args(action_method, args, page, self)
            missing = _missing_required_params(action_method, action_args)
            if missing:
                return [{"text": f"Error: Missing required parameter: {missing[0]}"}]

            result = await action_method(**action_args)
            return _format_action_result(result)

        for attempt in range(max_retries_local):
            try:
                return await execute_action()
            except Exception as error:
                if _is_non_retryable_error(error):
                    logger.error("Non-retryable error: %s", error)
                    return [{"text": f"Error: {str(error)}"}]

                if action == "evaluate" and isinstance(args.get("script"), str):
                    fixed_script = prepare_evaluate_script(args["script"])
                    if fixed_script != args["script"]:
                        args["script"] = fixed_script
                        logger.warning("Retrying evaluate with normalized JavaScript")
                        continue

                if attempt == max_retries_local - 1:
                    logger.error(
                        "Action '%s' failed after %s attempts: %s",
                        action,
                        max_retries_local,
                        error,
                    )
                    return [{"text": f"Error: {str(error)}"}]

                logger.warning(
                    "Action '%s' attempt %s failed: %s",
                    action,
                    attempt + 1,
                    error,
                )
                await asyncio.sleep(retry_delay_local * (2 ** attempt))

    BrowserApiMethods.get_text = staticmethod(patched_get_text)
    BrowserApiMethods.get_html = staticmethod(patched_get_html)
    BrowserManager.__init__ = patched_init
    BrowserManager.handle_action = patched_handle_action
    _PATCH_STATE["applied"] = True

    logger.info(
        "Successfully patched strands_tools.use_browser with timeout handling and evaluate normalization"
    )
    return True


apply_comprehensive_patch()
