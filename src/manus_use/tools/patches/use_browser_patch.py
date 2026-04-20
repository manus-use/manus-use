"""
Comprehensive patch for strands_tools.use_browser with timeout handling.

This module patches the actual use_browser.py file to fix:
1. Timeout handling for get_text/get_html
2. JavaScript syntax error fixing for evaluate
3. Better error messages with diagnostics
"""

import os
import sys

PATCH_FILE = None

if 'strands_tools' in sys.modules:
    try:
        import strands_tools.use_browser as use_browser_module
        PATCH_FILE = use_browser_module.__file__
    except ImportError:
        pass

if PATCH_FILE and os.path.exists(PATCH_FILE):
    with open(PATCH_FILE, 'r') as f:
        content = f.read()
    
    content = content.replace(
        'async def get_text(page: Page, selector: str):\n        text = await page.text_content(selector)\n        return f"Text content: {text}"',
        '''async def get_text(page: Page, selector: str, timeout_ms: int = None):
        timeout_ms = timeout_ms or int(os.getenv("STRANDS_BROWSER_DEFAULT_TIMEOUT", "10000"))
        try:
            text = await page.text_content(selector, timeout=timeout_ms)
            return f"Text content: {text}"
        except Exception as e:
            if "timeout" in str(e).lower():
                from manus_use.tools.browser_utils import get_text_with_fallback, BrowserTimeoutError
                try:
                    text, actual_sel = await get_text_with_fallback(
                        page, selector, timeout_ms, use_fallbacks=True
                    )
                    if actual_sel != selector:
                        return f"Text content (fallback '{actual_sel}'): {text}"
                    return f"Text content: {text}"
                except BrowserTimeoutError as te:
                    raise ValueError(
                        f"Element '{selector}' not found. Timeout: {timeout_ms}ms. "
                        f"Suggestions:\\n  1. Use get_html() to inspect page\\n  2. Try evaluate() to find elements\\n  3. Check if page loaded\\nError: {te}"
                    )
            raise'''
    )
    
    content = content.replace(
        'await page.wait_for_selector(selector, timeout=5000)',
        'await page.wait_for_selector(selector, timeout=timeout_ms or 10000)'
    )
    
    content = content.replace(
        'timeout=5000',
        'timeout=timeout_ms or int(os.getenv("STRANDS_BROWSER_DEFAULT_TIMEOUT", "10000"))'
    )
    
    content = content.replace(
        'retry_delay = int(os.getenv("STRANDS_BROWSER_RETRY_DELAY", 1))',
        'retry_delay = int(os.getenv("STRANDS_BROWSER_RETRY_DELAY", 2))'
    )
    
    patched_file = PATCH_FILE + '.patched'
    with open(patched_file, 'w') as f:
        f.write(content)


def apply_comprehensive_patch():
    """
    Apply comprehensive patch to use_browser module.
    
    This patches the actual source file to ensure:
    1. Timeout is configurable via environment variable
    2. Fallback selectors are tried when element not found
    3. Better error messages
    """
    try:
        import strands_tools.use_browser as use_browser_module
        from strands_tools.use_browser import BrowserApiMethods, BrowserManager
        import inspect
        
        DEFAULT_TIMEOUT = int(os.getenv("STRANDS_BROWSER_DEFAULT_TIMEOUT", "10000"))
        ENABLE_FALLBACKS = os.getenv("STRANDS_BROWSER_ENABLE_FALLBACKS", "true").lower() == "true"
        
        async def patched_get_text(page, selector, timeout_ms=None):
            """Patched get_text with timeout and fallback support."""
            timeout_ms = timeout_ms or DEFAULT_TIMEOUT
            
            try:
                text = await page.text_content(selector, timeout=timeout_ms)
                return f"Text content: {text}"
            except Exception as e:
                if "timeout" in str(e).lower() or "TimeoutError" in str(type(e).__name__):
                    from manus_use.tools.browser_utils import get_text_with_fallback, BrowserTimeoutError
                    
                    try:
                        text, actual_selector = await get_text_with_fallback(
                            page, selector, timeout_ms, use_fallbacks=ENABLE_FALLBACKS
                        )
                        if actual_selector != selector:
                            import logging
                            logging.getLogger(__name__).info(
                                f"Used fallback selector '{actual_selector}' instead of '{selector}'"
                            )
                            return f"Text content (fallback '{actual_selector}'): {text}"
                        return f"Text content: {text}"
                    except BrowserTimeoutError as te:
                        raise ValueError(
                            f"Element '{selector}' not found after {timeout_ms}ms. "
                            f"Tried fallbacks: {te.tried_fallbacks}. "
                            f"Suggestions:\\n  1. Use get_html() to inspect page structure\\n  "
                            f"2. Use evaluate() to find available elements\\n  "
                            f"3. Check if page is fully loaded"
                        )
                raise
        
        async def patched_get_html(page, selector=None, timeout_ms=None):
            """Patched get_html with configurable timeout."""
            from playwright.async_api import TimeoutError as PlaywrightTimeoutError
            timeout_ms = timeout_ms or DEFAULT_TIMEOUT
            
            if not selector:
                result = await page.content()
            else:
                try:
                    await page.wait_for_selector(selector, timeout=timeout_ms)
                    result = await page.inner_html(selector)
                except PlaywrightTimeoutError as e:
                    raise ValueError(
                        f"Element with selector '{selector}' not found on the page. "
                        f"Timeout: {timeout_ms}ms. "
                        f"Please verify the selector is correct."
                    )
            
            return (result[:1000] + "..." if len(result) > 1000 else result,)
        
        BrowserApiMethods.get_text = staticmethod(patched_get_text)
        BrowserApiMethods.get_html = staticmethod(patched_get_html)
        
        original_handle_action = BrowserManager.handle_action
        
        async def patched_handle_action(self, action, **kwargs):
            """Patched handle_action with timeout support."""
            max_retries = int(os.getenv("STRANDS_BROWSER_MAX_RETRIES", "3"))
            retry_delay = int(os.getenv("STRANDS_BROWSER_RETRY_DELAY", "2"))
            
            args = kwargs.get("args", {})
            
            async def execute_action():
                import inspect as insp
                
                if action not in self._actions:
                    return [{"text": f"Error: Unknown action {action}"}]
                
                action_method = self._actions[action]
                
                sig = insp.signature(action_method)
                required_params = [p for p in sig.parameters if sig.parameters[p].default == insp.Parameter.empty]
                for param in required_params:
                    if param not in args and param not in ["page", "browser_manager"]:
                        return [{"text": f"Error: Missing required parameter: {param}"}]
                
                page, _ = await self.ensure_browser(args.get("launchOptions"))
                
                action_args = {k: v for k, v in args.items() if k in sig.parameters}
                action_args["page"] = page
                if "browser_manager" in sig.parameters:
                    action_args["browser_manager"] = self
                
                timeout_ms = args.get("timeout_ms", DEFAULT_TIMEOUT)
                
                if action == "get_text":
                    action_args["timeout_ms"] = timeout_ms
                elif action == "get_html":
                    if "selector" in action_args:
                        action_args["timeout_ms"] = timeout_ms
                
                result = await action_method(**action_args)
                
                return [{"text": str(result)}]
            
            for attempt in range(max_retries):
                try:
                    return await execute_action()
                except Exception as e:
                    if attempt == max_retries - 1:
                        import logging
                        logging.getLogger(__name__).error(
                            f"Action '{action}' failed after {max_retries} attempts: {str(e)}"
                        )
                        return [{"text": f"Error: {str(e)}"}]
                    
                    import logging
                    logging.getLogger(__name__).warning(
                        f"Action '{action}' attempt {attempt + 1} failed: {str(e)}"
                    )
                    
                    if any(
                        err in str(e).lower()
                        for err in [
                            "could not resolve domain",
                            "connection refused",
                            "ssl/tls error",
                            "certificate error",
                            "protocol error (page.navigate): cannot navigate to invalid url",
                        ]
                    ):
                        import logging
                        logging.getLogger(__name__).error(f"Non-retryable error: {str(e)}")
                        return [{"text": f"Error: {str(e)}"}]
                    
                    if action == "evaluate" and "script" in args:
                        error_types = [
                            "SyntaxError",
                            "ReferenceError",
                            "TypeError",
                            "Illegal return",
                            "Unexpected token",
                            "Unexpected end",
                            "is not defined",
                        ]
                        if any(err_type in str(e) for err_type in error_types):
                            fixed_script = await self._fix_javascript_syntax(args["script"], str(e))
                            if fixed_script:
                                args["script"] = fixed_script
                                import logging
                                logging.getLogger(__name__).warning("Retrying with fixed JavaScript")
                                continue
                    
                    import asyncio
                    await asyncio.sleep(retry_delay * (2 ** attempt))
        
        BrowserManager.handle_action = patched_handle_action
        
        import logging
        logging.getLogger(__name__).info(
            "Successfully patched strands_tools.use_browser with timeout handling and fallback support"
        )
        
    except ImportError as e:
        import logging
        logging.getLogger(__name__).warning(f"Could not patch use_browser (not installed): {e}")
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to patch use_browser: {e}")


apply_comprehensive_patch()
