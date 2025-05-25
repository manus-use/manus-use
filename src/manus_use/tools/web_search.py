"""Web search tool for ManusUse."""

import asyncio
from typing import Dict, List, Optional

from strands.tools import tool

from ..config import Config


class SearchEngine:
    """Base search engine interface."""
    
    async def search(self, query: str, max_results: int = 5) -> List[Dict[str, str]]:
        """Search and return results."""
        raise NotImplementedError


class DuckDuckGoSearch(SearchEngine):
    """DuckDuckGo search implementation."""
    
    async def search(self, query: str, max_results: int = 5) -> List[Dict[str, str]]:
        """Search using DuckDuckGo."""
        try:
            from duckduckgo_search import DDGS
        except ImportError:
            raise ImportError("duckduckgo-search package is required for web search")
            
        # Run in thread pool since DDGS is synchronous
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._search_sync,
            query,
            max_results
        )
        
    def _search_sync(self, query: str, max_results: int) -> List[Dict[str, str]]:
        """Synchronous search implementation."""
        from duckduckgo_search import DDGS
        
        with DDGS() as ddgs:
            results = []
            for r in ddgs.text(query, max_results=max_results):
                results.append({
                    "title": r.get("title", ""),
                    "url": r.get("href", r.get("link", "")),  # Try both 'href' and 'link'
                    "snippet": r.get("body", ""),
                })
            return results


class GoogleSearch(SearchEngine):
    """Google search implementation."""
    
    def __init__(self, api_key: Optional[str] = None, cx: Optional[str] = None):
        self.api_key = api_key
        self.cx = cx
        
    async def search(self, query: str, max_results: int = 5) -> List[Dict[str, str]]:
        """Search using Google Custom Search API."""
        if not self.api_key or not self.cx:
            raise ValueError("Google search requires API key and custom search engine ID")
            
        # Implementation would use Google Custom Search API
        # For now, return empty results
        return []


# Global search engine instance
_search_engine = None


def get_search_engine(config: Optional[Config] = None) -> SearchEngine:
    """Get configured search engine."""
    global _search_engine
    if _search_engine is None:
        config = config or Config.from_file()
        
        if config.tools.search_engine == "duckduckgo":
            _search_engine = DuckDuckGoSearch()
        elif config.tools.search_engine == "google":
            # Would need API credentials from config
            _search_engine = GoogleSearch()
        else:
            _search_engine = DuckDuckGoSearch()  # Default
            
    return _search_engine


async def web_search_async(
    query: str,
    max_results: Optional[int] = None,
) -> List[Dict[str, str]]:
    """Search the web for information.
    
    Args:
        query: Search query
        max_results: Maximum number of results to return
        
    Returns:
        List of search results, each containing:
        - title: Page title
        - url: Page URL
        - snippet: Brief description
    """
    config = Config.from_file()
    max_results = max_results or config.tools.max_search_results
    
    engine = get_search_engine(config)
    
    try:
        results = await engine.search(query, max_results)
        return results
    except Exception as e:
        # Return error as single result
        return [{
            "title": "Search Error",
            "url": "",
            "snippet": f"Failed to search: {str(e)}"
        }]


@tool
def web_search(query: str, max_results: Optional[int] = None) -> List[Dict[str, str]]:
    """Search the web for information.
    
    Args:
        query: Search query
        max_results: Maximum number of results to return
        
    Returns:
        List of search results, each containing:
        - title: Page title
        - url: Page URL
        - snippet: Brief description
    """
    config = Config.from_file()
    max_results = max_results or config.tools.max_search_results
    
    engine = get_search_engine(config)
    
    try:
        # Use the synchronous search method directly
        if hasattr(engine, '_search_sync'):
            return engine._search_sync(query, max_results)
        else:
            # Fallback to running async in new event loop
            import nest_asyncio
            nest_asyncio.apply()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(engine.search(query, max_results))
            finally:
                loop.close()
    except Exception as e:
        # Return error as single result
        return [{
            "title": "Search Error",
            "url": "",
            "snippet": f"Failed to search: {str(e)}"
        }]


# Alias for backward compatibility
web_search_sync = web_search