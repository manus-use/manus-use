"""
Patched version of strands_tools.use_browser with improved error handling.

This module provides drop-in replacements for the browser API methods with:
1. Proper timeout handling
2. Fallback behavior for missing elements
3. Better logging and diagnostics
4. Configurable timeouts
"""

import asyncio
import logging
import os
from typing import Dict, List, Optional, Any

from playwright.async_api import Page, TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = int(os.getenv("STRANDS_BROWSER_DEFAULT_TIMEOUT", "10000"))
ENABLE_FALLBACKS = os.getenv("STRANDS_BROWSER_ENABLE_FALLBACKS", "true").lower() == "true"


class PatchedBrowserApiMethods:
    """Improved browser API methods with error handling and fallbacks."""
    
    @staticmethod
    async def get_text(
        page: Page,
        selector: str,
        timeout_ms: int = DEFAULT_TIMEOUT,
        use_fallbacks: bool = True,
    ) -> str:
        """
        Get text content with timeout handling and fallback support.
        
        Args:
            page: Playwright Page object
            selector: CSS selector
            timeout_ms: Timeout in milliseconds
            use_fallbacks: Try fallback selectors if primary fails
        
        Returns:
            Text content string
        
        Raises:
            ValueError: If element not found and no fallbacks work
        """
        from .browser_utils import get_text_with_fallback, BrowserTimeoutError
        
        try:
            text, actual_selector = await get_text_with_fallback(
                page, selector, timeout_ms, use_fallbacks
            )
            if actual_selector != selector:
                return f"Text content (using fallback '{actual_selector}'): {text}"
            return f"Text content: {text}"
            
        except BrowserTimeoutError as e:
            logger.error(f"get_text failed: {e}")
            raise ValueError(
                f"Element with selector '{selector}' not found on the page. "
                f"Timeout: {timeout_ms}ms. "
                f"Troubleshooting:\n"
                f"  1. Use get_html() to inspect the page structure\n"
                f"  2. Use evaluate() to find available elements\n"
                f"  3. Check if the page has fully loaded\n"
                f"Original error: {e}"
            )
    
    @staticmethod
    async def get_html(
        page: Page,
        selector: str = None,
        timeout_ms: int = DEFAULT_TIMEOUT,
    ) -> str:
        """
        Get HTML content with improved error handling.
        
        Args:
            page: Playwright Page object
            selector: CSS selector (optional)
            timeout_ms: Timeout in milliseconds
        
        Returns:
            HTML content string (truncated if too long)
        """
        from .browser_utils import get_html_with_fallback, BrowserTimeoutError
        
        try:
            result = await get_html_with_fallback(page, selector, timeout_ms)
            truncated = result[:1000] + "..." if len(result) > 1000 else result
            return truncated
            
        except BrowserTimeoutError as e:
            logger.error(f"get_html failed: {e}")
            raise ValueError(
                f"Element with selector '{selector}' not found on the page. "
                f"Timeout: {timeout_ms}ms. "
                f"Please verify the selector is correct. "
                f"Try get_html() without selector for full page content."
            )
    
    @staticmethod
    async def extract_content(
        page: Page,
        goal: str = "extract main content",
        timeout_ms: int = DEFAULT_TIMEOUT,
    ) -> str:
        """
        Intelligently extract content from page.
        
        This method automatically finds the best content area and extracts text.
        
        Args:
            page: Playwright Page object
            goal: Description of what to extract
            timeout_ms: Timeout in milliseconds
        
        Returns:
            Extracted content
        """
        from .browser_utils import extract_page_text
        
        result = await extract_page_text(page, timeout_ms)
        
        output = f"Extracted content (method: {result['method']}, selector: {result['selector']}):\n"
        output += result['text']
        return output
    
    @staticmethod
    async def find_elements(
        page: Page,
        element_type: str = "all",
    ) -> str:
        """
        Find elements on the page to help identify correct selectors.
        
        Args:
            page: Playwright Page object
            element_type: Type of elements to find ('all', 'content', 'interactive')
        
        Returns:
            JSON string describing found elements
        """
        import json
        
        script = """
        () => {
            const results = [];
            
            // Find content containers
            const contentSelectors = ['article', 'main', '#content', '.content', '.post', '.article'];
            for (const sel of contentSelectors) {
                const elements = document.querySelectorAll(sel);
                if (elements.length > 0) {
                    results.push({
                        type: 'content',
                        selector: sel,
                        count: elements.length,
                        sample: elements[0].innerText?.substring(0, 100) || ''
                    });
                }
            }
            
            // Find interactive elements
            const interactiveSelectors = ['button', 'input', 'a', 'select', 'textarea'];
            for (const sel of interactiveSelectors) {
                const elements = document.querySelectorAll(sel);
                if (elements.length > 0) {
                    results.push({
                        type: 'interactive',
                        selector: sel,
                        count: elements.length
                    });
                }
            }
            
            // Find headings
            for (let i = 1; i <= 6; i++) {
                const elements = document.querySelectorAll(`h${i}`);
                if (elements.length > 0) {
                    results.push({
                        type: 'heading',
                        selector: `h${i}`,
                        count: elements.length,
                        samples: Array.from(elements).slice(0, 3).map(e => e.innerText)
                    });
                }
            }
            
            return results;
        }
        """
        
        try:
            results = await page.evaluate(script)
            return json.dumps(results, indent=2)
        except Exception as e:
            return f"Error finding elements: {e}"


def patch_use_browser():
    """
    Patch the strands_tools.use_browser module with improved methods.
    
    This function monkey-patches the BrowserApiMethods class in strands_tools
    to use the improved implementations with better error handling.
    
    Usage:
        from manus_use.tools.patches.use_browser_patch import patch_use_browser
        patch_use_browser()
        
        # Now use_browser will have improved error handling
        from strands_tools import use_browser
    """
    try:
        import strands_tools.use_browser as use_browser_module
        from strands_tools.use_browser import BrowserApiMethods
        
        original_get_text = BrowserApiMethods.get_text
        original_get_html = BrowserApiMethods.get_html
        
        async def patched_get_text(page: Page, selector: str):
            return await PatchedBrowserApiMethods.get_text(
                page, selector, DEFAULT_TIMEOUT, ENABLE_FALLBACKS
            )
        
        async def patched_get_html(page: Page, selector: str = None):
            return await PatchedBrowserApiMethods.get_html(
                page, selector, DEFAULT_TIMEOUT
            )
        
        BrowserApiMethods.get_text = staticmethod(patched_get_text)
        BrowserApiMethods.get_html = staticmethod(patched_get_html)
        
        if not hasattr(BrowserApiMethods, 'extract_content'):
            BrowserApiMethods.extract_content = staticmethod(PatchedBrowserApiMethods.extract_content)
        
        if not hasattr(BrowserApiMethods, 'find_elements'):
            BrowserApiMethods.find_elements = staticmethod(PatchedBrowserApiMethods.find_elements)
        
        logger.info("Successfully patched strands_tools.use_browser with improved error handling")
        
    except ImportError as e:
        logger.warning(f"Could not patch use_browser (module not found): {e}")
    except Exception as e:
        logger.error(f"Failed to patch use_browser: {e}", exc_info=True)
