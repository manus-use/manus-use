"""Tool for fetching the PoC Week digest from tonyharris.io.

PoC Week is a weekly digest of the most-mentioned CVEs across security
newsletters, pre-filtered to only include CVEs with public Proof-of-Concepts
and ordered by community mention count.  It acts as a "trending" signal on
top of raw NVD/EPSS data.

URL pattern: https://tonyharris.io/poc-week/poc-week-YYYYMMDD/
Index page:  https://tonyharris.io/poc-week/
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

__all__ = ["get_poc_week"]

_BASE_URL = "https://tonyharris.io"
_INDEX_URL = f"{_BASE_URL}/poc-week/"
_USER_AGENT = "manus-use/poc-week-tool (github.com/manus-use/manus-use)"

# Matches "CVE-YYYY-NNNNN" (standard NVD format)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# Matches section headings — markdown (## CVE-…) OR HTML (<h2>CVE-…</h2>)
_HEADING_RE = re.compile(
    r"^(?:#{1,3}\s+|<h[1-3]>)(CVE-\d{4}-\d{4,7})\b(.*?)(?:</h[1-3]>)?$",
    re.IGNORECASE | re.MULTILINE,
)
# PoC URL lines: lines that start with a bare URL or a markdown link
_POC_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


def _fetch_url(url: str, timeout: int = 15) -> str:
    """Fetch *url* and return the response body as a UTF-8 string."""
    req = Request(url, headers={"User-Agent": _USER_AGENT})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read().decode("utf-8", errors="replace")


def _last_sunday(ref: date | None = None) -> date:
    """Return the most recent Sunday on or before *ref* (defaults to today)."""
    ref = ref or date.today()
    # weekday(): Mon=0 … Sun=6
    days_since_sunday = (ref.weekday() + 1) % 7
    return ref - timedelta(days=days_since_sunday)


def _url_for_date(d: date) -> str:
    return f"{_BASE_URL}/poc-week/poc-week-{d.strftime('%Y%m%d')}/"


def _parse_poc_week(html: str) -> list[dict[str, Any]]:
    """Parse a PoC Week HTML page and return a list of CVE entries.

    Each entry is a dict::

        {
            "cve_id":        str,           # e.g. "CVE-2026-32201"
            "severity":      str | None,    # e.g. "9.8 CRITICAL"
            "products":      str | None,    # impacted products
            "description":   str | None,    # short description
            "poc_urls":      list[str],     # PoC links found
            "is_new":        bool,          # True if "NEW" tag present
            "mention_rank":  int,           # 1-based order on the page
        }
    """
    results: list[dict[str, Any]] = []

    # Split into per-CVE sections by h2/h3 headings — supports both
    # markdown (## CVE-…) and HTML (<h2>CVE-…</h2>) heading styles.
    sections = re.split(
        r"\n(?=(?:#{1,3}\s+|<h[1-3]>)CVE-)", html, flags=re.IGNORECASE
    )

    rank = 0
    for section in sections:
        heading_match = _HEADING_RE.match(section.lstrip())
        if not heading_match:
            continue

        rank += 1
        cve_id = heading_match.group(1).upper()
        is_new = "NEW" in heading_match.group(2).upper()

        # Severity line: "- Severity: 9.8 CRITICAL"
        severity_match = re.search(
            r"-\s*Severity:\s*(.+?)(?:\n|$)", section, re.IGNORECASE
        )
        severity = severity_match.group(1).strip() if severity_match else None

        # Impacted products
        products_match = re.search(
            r"-\s*Impacted Products?:\s*(.+?)(?:\n|$)", section, re.IGNORECASE
        )
        products = products_match.group(1).strip() if products_match else None

        # Description (first paragraph after "Description:")
        desc_match = re.search(
            r"-\s*Description:\s*([\s\S]+?)(?:\n-\s|\Z)", section, re.IGNORECASE
        )
        description: str | None = None
        if desc_match:
            description = " ".join(desc_match.group(1).split())

        # PoC URLs — lines after a "PoC:" marker
        poc_section_match = re.search(
            r"-\s*PoC:\s*([\s\S]+?)(?:\n-\s[A-Z]|\Z)", section, re.IGNORECASE
        )
        poc_urls: list[str] = []
        if poc_section_match:
            raw = poc_section_match.group(1)
            poc_urls = _POC_URL_RE.findall(raw)
            # Strip trailing markdown punctuation
            poc_urls = [u.rstrip(").,]") for u in poc_urls]

        results.append(
            {
                "cve_id": cve_id,
                "severity": severity,
                "products": products,
                "description": description,
                "poc_urls": poc_urls,
                "is_new": is_new,
                "mention_rank": rank,
            }
        )

    return results


def get_poc_week(
    date_str: str | None = None,
    *,
    timeout: int = 15,
    max_retries: int = 3,
) -> dict[str, Any]:
    """Fetch a PoC Week digest from tonyharris.io.

    Retrieves the weekly digest of trending CVEs with public Proof-of-Concept
    exploits, curated from security newsletters and ranked by mention count.

    Args:
        date_str: ISO date string (YYYY-MM-DD) for the desired week.  The
            tool will round back to the nearest Sunday automatically.  If
            *None*, defaults to the most recent available Sunday.  When the
            exact date returns 404, the tool walks back up to *max_retries*
            prior weeks looking for published content.
        timeout: HTTP request timeout in seconds.
        max_retries: Number of prior weeks to try on 404 before giving up.

    Returns:
        A dict with keys:

        - ``"week_date"`` – ISO date string of the retrieved issue (YYYY-MM-DD)
        - ``"url"`` – canonical URL of the fetched page
        - ``"cves"`` – list of CVE entry dicts, each containing:
            - ``"cve_id"``       – e.g. ``"CVE-2026-32201"``
            - ``"mention_rank"`` – 1-based position (lower = more buzz)
            - ``"severity"``     – severity string or *None*
            - ``"products"``     – impacted products string or *None*
            - ``"description"``  – short description or *None*
            - ``"poc_urls"``     – list of PoC/exploit URLs
            - ``"is_new"``       – *True* if marked NEW in the digest
        - ``"total"``  – number of CVEs found
        - ``"error"``  – error message string, only present on failure

    Examples::

        # Latest available issue
        result = get_poc_week()

        # Specific week (rounds to nearest Sunday)
        result = get_poc_week("2026-04-27")

        # Access results
        for entry in result["cves"]:
            print(entry["cve_id"], entry["mention_rank"], entry["poc_urls"])
    """
    # Resolve target date
    if date_str:
        try:
            ref = date.fromisoformat(date_str)
        except ValueError:
            return {"error": f"Invalid date format: {date_str!r}. Use YYYY-MM-DD."}
    else:
        ref = date.today()

    target = _last_sunday(ref)

    # Try target date, then walk back on 404
    html: str | None = None
    fetched_date: date | None = None
    last_error: str = ""

    for attempt in range(max_retries + 1):
        candidate = target - timedelta(weeks=attempt)
        url = _url_for_date(candidate)
        try:
            html = _fetch_url(url, timeout=timeout)
            fetched_date = candidate
            break
        except HTTPError as exc:
            if exc.code == 404:
                last_error = f"404 for {url}"
                continue
            return {"error": f"HTTP {exc.code} fetching {url}: {exc.reason}"}
        except URLError as exc:
            return {"error": f"Network error fetching {url}: {exc.reason}"}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"Unexpected error fetching {url}: {exc}"}

    if html is None or fetched_date is None:
        return {
            "error": (
                f"No PoC Week issue found within {max_retries} weeks of "
                f"{target.isoformat()}. Last error: {last_error}"
            )
        }

    cves = _parse_poc_week(html)

    return {
        "week_date": fetched_date.isoformat(),
        "url": _url_for_date(fetched_date),
        "cves": cves,
        "total": len(cves),
    }
