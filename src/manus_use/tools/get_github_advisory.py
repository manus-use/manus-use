"""Tool to fetch data from the GitHub Advisory Database."""

import requests
from strands.tools import tool
from typing import Dict, Any

@tool
def get_github_advisory(cve_id: str) -> Dict[str, Any]:
    """
    Fetches vulnerability advisory information from the GitHub Advisory Database for a given CVE ID.

    This tool queries the public GitHub REST API to find advisories associated with a specific CVE identifier.

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2023-1234").

    Returns:
        A dictionary containing the advisory data from GitHub if found, otherwise a message indicating it was not found or an error.
    """
    if not cve_id or not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
        return {"error": "Invalid CVE ID format. It must be a string starting with 'CVE-'."}

    # Use the official GitHub REST API endpoint for getting advisories by CVE ID.
    url = f"https://api.github.com/advisories?cve_id={cve_id}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if not data:
            return {"message": f"No advisory found on GitHub for {cve_id}."}
        
        # The API returns a list of advisories; we will return the first and most relevant one.
        return data[0]

    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 404:
            return {"message": f"No advisory found on GitHub for {cve_id}."}
        return {"error": f"HTTP error occurred while querying GitHub Advisory API: {http_err}"}
    except requests.exceptions.RequestException as req_err:
        return {"error": f"An error occurred while querying the GitHub Advisory API: {req_err}"}
    except (KeyError, IndexError):
        return {"error": "Received an unexpected response format from the GitHub Advisory API."}
