"""
Browser tool utilities with improved error handling and timeout management.

This module provides a patched version of browser operations with better
error handling, fallback behavior, and diagnostics for missing elements.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from playwright.async_api import Page, TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = 10000
FALLBACK_SELECTORS = {
    "article": ["article", "main", ".article", ".post", ".content", "#content", "body"],
    "main": ["main", "#main", ".main", "article", ".content", "body"],
    "content": ["#content", ".content", "main", "article", ".post", "body"],
}


class BrowserTimeoutError(Exception):
    """Custom exception for browser timeout with diagnostic information."""
    
    def __init__(
        self,
        selector: str,
        timeout_ms: int,
        url: Optional[str] = None,
        tried_fallbacks: Optional[List[str]] = None,
    ):
        self.selector = selector
        self.timeout_ms = timeout_ms
        self.url = url
        self.tried_fallbacks = tried_fallbacks or []
        
        msg = f"Timeout ({timeout_ms}ms) waiting for element: '{selector}'"
        if url:
            msg += f" on page: {url}"
        if self.tried_fallbacks:
            msg += f"\n  Tried fallback selectors: {self.tried_fallbacks}"
        msg += "\n  Suggestions:"
        msg += "\n    1. Verify the selector is correct"
        msg += "\n    2. Check if page is fully loaded"
        msg += "\n    3. Use get_html() to inspect page structure"
        msg += "\n    4. Use evaluate() to find elements dynamically"
        
        super().__init__(msg)


async def get_text_with_fallback(
    page: Page,
    selector: str,
    timeout_ms: int = DEFAULT_TIMEOUT,
    use_fallbacks: bool = True,
) -> Tuple[str, Optional[str]]:
    """
    Get text content from an element with fallback support and better error handling.
    
    Args:
        page: Playwright Page object
        selector: CSS selector for the element
        timeout_ms: Timeout in milliseconds (default: 10000)
        use_fallbacks: Whether to try fallback selectors (default: True)
    
    Returns:
        Tuple of (text_content, actual_selector_used)
        
    Raises:
        BrowserTimeoutError: If element not found after timeout and fallbacks
    """
    selectors_to_try = [selector]
    
    if use_fallbacks:
        for key, fallbacks in FALLBACK_SELECTORS.items():
            if selector.lower() == key or selector.lower() in f"<{key}>":
                for fb in fallbacks:
                    if fb not in selectors_to_try:
                        selectors_to_try.append(fb)
    
    errors = []
    url = None
    
    try:
        url = page.url
    except Exception:
        pass
    
    for sel in selectors_to_try:
        try:
            text = await page.text_content(sel, timeout=timeout_ms)
            if text is not None:
                if sel != selector:
                    logger.info(f"Used fallback selector '{sel}' instead of '{selector}'")
                return text, sel
            else:
                errors.append(f"'{sel}': element found but no text content")
        except PlaywrightTimeoutError:
            errors.append(f"'{sel}': timeout after {timeout_ms}ms")
            continue
        except Exception as e:
            errors.append(f"'{sel}': {type(e).__name__}: {str(e)[:50]}")
            continue
    
    raise BrowserTimeoutError(
        selector=selector,
        timeout_ms=timeout_ms,
        url=url,
        tried_fallbacks=selectors_to_try,
    )


async def get_html_with_fallback(
    page: Page,
    selector: Optional[str] = None,
    timeout_ms: int = DEFAULT_TIMEOUT,
) -> str:
    """
    Get HTML content with better error handling and diagnostics.
    
    Args:
        page: Playwright Page object
        selector: CSS selector for specific element (optional)
        timeout_ms: Timeout in milliseconds (default: 10000)
    
    Returns:
        HTML content string
        
    Raises:
        BrowserTimeoutError: If element not found after timeout
    """
    url = None
    try:
        url = page.url
    except Exception:
        pass
    
    try:
        if not selector:
            result = await page.content()
            return result
        
        await page.wait_for_selector(selector, timeout=timeout_ms)
        result = await page.inner_html(selector)
        return result
        
    except PlaywrightTimeoutError:
        raise BrowserTimeoutError(
            selector=selector or "full page",
            timeout_ms=timeout_ms,
            url=url,
        )
    except Exception as e:
        logger.error(f"Error getting HTML: {e}")
        raise


async def find_best_content_selector(page: Page) -> str:
    """
    Find the best selector for main content on the page.
    
    Tries common content selectors in order of preference.
    
    Args:
        page: Playwright Page object
    
    Returns:
        Best selector found, or "body" as fallback
    """
    candidates = [
        ("article", "article"),
        ("main", "main"),
        ("#content", "div#content"),
        (".content", "div.content"),
        (".post", "div.post"),
        (".article", "div.article"),
        ("body", "body"),
    ]
    
    for name, selector in candidates:
        try:
            element = await page.query_selector(selector)
            if element:
                text = await element.text_content()
                if text and len(text.strip()) > 100:
                    logger.debug(f"Found content selector: {selector}")
                    return selector
        except Exception:
            continue
    
    return "body"


async def extract_page_text(page: Page, timeout_ms: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Extract text content from page with intelligent selector detection.
    
    This is a high-level function that:
    1. Tries to find the best content selector
    2. Extracts text with fallbacks
    3. Returns comprehensive results with diagnostics
    
    Args:
        page: Playwright Page object
        timeout_ms: Timeout in milliseconds
    
    Returns:
        Dictionary with:
        - text: Extracted text content
        - selector: Selector that was used
        - url: Page URL
        - method: Method used to extract text
    """
    result = {
        "text": "",
        "selector": None,
        "url": None,
        "method": None,
    }
    
    try:
        result["url"] = page.url
    except Exception:
        pass
    
    best_selector = await find_best_content_selector(page)
    
    try:
        text, actual_selector = await get_text_with_fallback(
            page, best_selector, timeout_ms=timeout_ms, use_fallbacks=True
        )
        result["text"] = text
        result["selector"] = actual_selector
        result["method"] = "text_content"
        return result
        
    except BrowserTimeoutError as e:
        logger.warning(f"get_text_with_fallback failed: {e}")
        
    try:
        html = await get_html_with_fallback(page, timeout_ms=timeout_ms)
        result["text"] = html[:5000]
        result["selector"] = "full page"
        result["method"] = "html_content"
        return result
        
    except Exception as e:
        logger.error(f"Fallback to HTML also failed: {e}")
        
    try:
        text = await page.evaluate("() => document.body.innerText")
        result["text"] = text or ""
        result["selector"] = "body"
        result["method"] = "javascript_innerText"
        return result
        
    except Exception as e:
        logger.error(f"All text extraction methods failed: {e}")
        result["text"] = f"Error: Could not extract text from page. {str(e)}"
        result["method"] = "error"
        return result


def format_browser_error(error: Exception, context: Optional[Dict[str, Any]] = None) -> str:
    """
    Format browser errors with helpful diagnostic information.
    
    Args:
        error: The exception that occurred
        context: Optional context dictionary (url, selector, etc.)
    
    Returns:
        Formatted error message with suggestions
    """
    context = context or {}
    lines = [f"Browser Error: {type(error).__name__}: {str(error)}"]
    
    if context.get("url"):
        lines.append(f"  URL: {context['url']}")
    if context.get("selector"):
        lines.append(f"  Selector: {context['selector']}")
    
    if isinstance(error, PlaywrightTimeoutError):
        lines.extend([
            "",
            "Timeout Suggestions:",
            "  1. The element may not exist on the page",
            "  2. The page may still be loading (try wait action)",
            "  3. The selector may be incorrect",
            "  4. Use get_html() to inspect page structure",
            "  5. Use evaluate() to find elements: document.querySelectorAll('*')",
        ])
    elif isinstance(error, BrowserTimeoutError):
        pass
    
    return "\n".join(lines)
