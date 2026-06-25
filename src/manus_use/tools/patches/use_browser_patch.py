"""Compatibility patch for ``strands_tools.use_browser`` actions.

This patch focuses on three general browser execution issues:
1. Safely propagating optional timeout arguments only to compatible actions.
2. Normalizing ``evaluate`` scripts into valid Playwright callables.
3. Rebinding stale action registrations so patched methods are actually invoked.
"""

import asyncio
import importlib
import inspect
import logging
import os
import threading
import warnings
from collections.abc import Callable
from typing import Any

from manus_use.tools.browser_utils import (
    BrowserTimeoutError,
    get_html_with_fallback,
    get_text_with_fallback,
    is_selector_syntax_error,
    normalize_browser_selector,
    prepare_evaluate_script,
)

logger = logging.getLogger(__name__)

_PATCH_CONFIG: dict[str, Any] = {
    "default_timeout_ms": int(os.getenv("STRANDS_BROWSER_DEFAULT_TIMEOUT", "10000")),
    "max_retries": int(os.getenv("STRANDS_BROWSER_MAX_RETRIES", "3")),
    "retry_delay_seconds": int(os.getenv("STRANDS_BROWSER_RETRY_DELAY", "2")),
    "enable_fallbacks": os.getenv("STRANDS_BROWSER_ENABLE_FALLBACKS", "true").lower() == "true",
}
_PATCH_STATE: dict[str, Any] = {
    "applied": False,
    "original_init": None,
    "original_handle_action": None,
    "asyncio_compat_applied": False,
    "original_shutdown_default_executor": {},
    "original_sniffio_current_async_library": None,
    "original_sniffio_impl_current_async_library": None,
    "original_httpcore_async_shield_cancellation": {},
}


async def _shutdown_default_executor_without_wait_for(self, timeout=None):
    """Shutdown the default executor without ``asyncio.wait_for``.

    Python 3.14 changed ``shutdown_default_executor`` to use timeout helpers
    that require ``asyncio.current_task()``. Browser integrations that apply
    ``nest_asyncio`` can run loop cleanup handles without a current task, which
    turns otherwise harmless shutdown/cleanup into noisy background exceptions.
    Use manual ``call_later`` timeout handling instead.
    """
    self._executor_shutdown_called = True
    if self._default_executor is None:
        return

    future = self.create_future()
    thread = threading.Thread(target=self._do_shutdown, args=(future,))
    thread.start()
    timeout_handle = None

    if timeout is not None:
        timeout_handle = self.call_later(timeout, future.cancel)

    try:
        await future
    except asyncio.CancelledError:
        warnings.warn(
            f"The executor did not finish joining its threads within {timeout} seconds.",
            RuntimeWarning,
            stacklevel=2,
        )
        self._default_executor.shutdown(wait=False)
    else:
        thread.join()
    finally:
        if timeout_handle is not None:
            timeout_handle.cancel()


def _current_asyncio_task_or_none():
    """Return the current asyncio task, or None outside a real task context."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return None

    try:
        return asyncio.current_task()
    except RuntimeError:
        return None


def apply_asyncio_compat_patch() -> bool:
    """Apply process-wide asyncio compatibility patches used by browser tools.

    Returns ``True`` when the patch was applied during this call, otherwise
    ``False`` when it had already been applied. The patch is intentionally
    idempotent because entrypoints and browser agents may both call it.
    """
    if _PATCH_STATE["asyncio_compat_applied"]:
        return False

    loop_classes = [asyncio.SelectorEventLoop]
    proactor_loop = getattr(asyncio, "ProactorEventLoop", None)
    if proactor_loop is not None:
        loop_classes.append(proactor_loop)

    for loop_class in loop_classes:
        _PATCH_STATE["original_shutdown_default_executor"][loop_class] = getattr(
            loop_class, "shutdown_default_executor", None
        )
        loop_class.shutdown_default_executor = _shutdown_default_executor_without_wait_for

    try:
        import sniffio
        import sniffio._impl as sniffio_impl
    except ImportError:
        sniffio = None
        sniffio_impl = None

    if sniffio is not None and sniffio_impl is not None:
        original_current_async_library = sniffio.current_async_library
        original_impl_current_async_library = sniffio_impl.current_async_library

        def current_async_library_with_asyncio_fallback():
            try:
                return original_impl_current_async_library()
            except sniffio.AsyncLibraryNotFoundError:
                if _current_asyncio_task_or_none() is None:
                    raise
                return "asyncio"

        _PATCH_STATE["original_sniffio_current_async_library"] = original_current_async_library
        _PATCH_STATE["original_sniffio_impl_current_async_library"] = original_impl_current_async_library
        sniffio.current_async_library = current_async_library_with_asyncio_fallback
        sniffio_impl.current_async_library = current_async_library_with_asyncio_fallback

    try:
        import sniffio as sniffio_for_httpcore
    except ImportError:
        sniffio_for_httpcore = None

    httpcore_module_names = (
        "httpcore._synchronization",
        "httpcore._async.http11",
        "httpcore._async.http2",
        "httpcore._async.connection_pool",
    )
    original_shields = _PATCH_STATE["original_httpcore_async_shield_cancellation"]

    for module_name in httpcore_module_names:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue

        original_async_shield = getattr(module, "AsyncShieldCancellation", None)
        if original_async_shield is None:
            continue
        original_shields[module_name] = original_async_shield

    if original_shields:
        canonical_original_async_shield = original_shields.get("httpcore._synchronization") or next(
            iter(original_shields.values())
        )

        class AsyncShieldCancellationCompat:
            """httpcore cleanup shield that no-ops outside an asyncio task.

            httpcore shields async stream cleanup with AnyIO ``CancelScope``. On
            Python 3.14/nested-loop cleanup paths, there can be a running loop
            but no current task, and AnyIO cannot enter a cancel scope there.
            """

            def __init__(self, *args, **kwargs):
                self._backend = None
                self._entered = False
                self._inner = None
                self._noop = False

                if sniffio_for_httpcore is None:
                    self._noop = True
                    return

                try:
                    self._backend = sniffio_for_httpcore.current_async_library()
                except sniffio_for_httpcore.AsyncLibraryNotFoundError:
                    self._noop = True
                    return

                if self._backend == "asyncio" and _current_asyncio_task_or_none() is None:
                    self._noop = True
                    return

                self._inner = canonical_original_async_shield(*args, **kwargs)

            def __enter__(self):
                if self._noop or self._inner is None:
                    return self

                if self._backend == "asyncio" and _current_asyncio_task_or_none() is None:
                    self._noop = True
                    self._inner = None
                    return self

                try:
                    self._inner.__enter__()
                except TypeError as exc:
                    if "cannot create weak reference to 'NoneType' object" not in str(exc):
                        raise
                    self._noop = True
                    self._inner = None
                    return self

                self._entered = True
                return self

            def __exit__(self, exc_type=None, exc_value=None, traceback=None):
                if self._entered and self._inner is not None:
                    return self._inner.__exit__(exc_type, exc_value, traceback)
                return None

        for module_name in original_shields:
            try:
                module = importlib.import_module(module_name)
            except ImportError:
                continue
            module.AsyncShieldCancellation = AsyncShieldCancellationCompat

    _PATCH_STATE["asyncio_compat_applied"] = True
    return True


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
    default_timeout_ms: int | None = None,
    max_retries: int | None = None,
    retry_delay_seconds: int | None = None,
    enable_fallbacks: bool | None = None,
) -> dict[str, Any]:
    """Update runtime patch configuration and return the active settings."""
    if default_timeout_ms is not None:
        _PATCH_CONFIG["default_timeout_ms"] = _coerce_int(default_timeout_ms, _PATCH_CONFIG["default_timeout_ms"])
    if max_retries is not None:
        _PATCH_CONFIG["max_retries"] = _coerce_int(max_retries, _PATCH_CONFIG["max_retries"])
    if retry_delay_seconds is not None:
        _PATCH_CONFIG["retry_delay_seconds"] = _coerce_int(retry_delay_seconds, _PATCH_CONFIG["retry_delay_seconds"])
    if enable_fallbacks is not None:
        _PATCH_CONFIG["enable_fallbacks"] = bool(enable_fallbacks)
    return dict(_PATCH_CONFIG)


def _get_timeout_ms(args: dict[str, Any]) -> int:
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


def _resolve_action_method(browser_manager: Any, browser_api_methods: Any, action: str) -> Callable[..., Any] | None:
    _rebind_action_registry(browser_manager, browser_api_methods)

    actions = getattr(browser_manager, "_actions", None)
    if isinstance(actions, dict) and action in actions:
        return actions[action]

    direct_method = getattr(browser_api_methods, action, None)
    if callable(direct_method):
        return direct_method
    return None


def _build_action_args(
    action_method: Callable[..., Any], args: dict[str, Any], page: Any, browser_manager: Any
) -> dict[str, Any]:
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


def _missing_required_params(action_method: Callable[..., Any], action_args: dict[str, Any]) -> list[str]:
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
    default_timeout_ms: int | None = None,
    max_retries: int | None = None,
    retry_delay_seconds: int | None = None,
    enable_fallbacks: bool | None = None,
) -> bool:
    """Apply a compatibility patch to ``strands_tools.use_browser`` if available."""
    apply_asyncio_compat_patch()
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
                await asyncio.sleep(retry_delay_local * (2**attempt))

    BrowserApiMethods.get_text = staticmethod(patched_get_text)
    BrowserApiMethods.get_html = staticmethod(patched_get_html)
    BrowserManager.__init__ = patched_init
    BrowserManager.handle_action = patched_handle_action
    _PATCH_STATE["applied"] = True

    logger.info("Successfully patched strands_tools.use_browser with timeout handling and evaluate normalization")
    return True


if __name__ == "__main__":
    apply_comprehensive_patch()
