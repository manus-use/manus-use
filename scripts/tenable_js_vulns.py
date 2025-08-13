#!/usr/bin/env python3
import requests
import json
import os
from datetime import datetime
import sys
from tabulate import tabulate

def query_tenable_api():
    """
    Query the Tenable API for JavaScript vulnerabilities from May 2025
    """
    # Tenable API credentials should be set as environment variables
    access_key = os.environ.get('TENABLE_ACCESS_KEY')
    secret_key = os.environ.get('TENABLE_SECRET_KEY')
    
    if not access_key or not secret_key:
        print("Error: Tenable API credentials not found in environment variables.")
        print("Please set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY environment variables.")
        return None
    
    # Tenable.io API endpoint for vulnerability search
    url = "https://cloud.tenable.com/vulns/search"
    
    # Headers for authentication
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }
    
    # Filter for JavaScript vulnerabilities from May 2025
    # May 2025 date range: 2025-05-01 to 2025-05-31
    payload = {
        "filters": {
            "text_search": "javascript",
            "published_date": {
                "start": "2025-05-01",
                "end": "2025-05-31"
            }
        },
        "limit": 10,
        "sort": [{"field": "published_date", "direction": "desc"}]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()  # Raise exception for HTTP errors
        return response.json()
            
    except requests.exceptions.RequestException as e:
        print(f"Error querying Tenable API: {e}")
        return None

def main():
    print("Querying Tenable API for JavaScript vulnerabilities from May 2025...")
    
    # Query the API
    data = query_tenable_api()
    
    if not data or 'vulnerabilities' not in data:
        print("No vulnerabilities found or API query failed.")
        return
    
    vulnerabilities = data['vulnerabilities']
    print(f"Found {len(vulnerabilities)} JavaScript vulnerabilities from May 2025.\n")
    
    # Prepare data for tabular display
    table_data = []
    for vuln in vulnerabilities:
        plugin = vuln.get('plugin', {})
        cves = ', '.join(plugin.get('cve', ['N/A']))
        
        # Truncate description for display
        description = plugin.get('description', 'No description available')
        if len(description) > 100:
            description = description[:97] + '...'
        
        table_data.append([
            plugin.get('name', 'Unknown'),
            cves,
            vuln.get('severity', 'Unknown'),
            plugin.get('publication_date', 'Unknown'),
            description
        ])
    
    # Display results in a table
    headers = ["Name", "CVE", "Severity", "Published Date", "Description"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Save results to a JSON file
    with open("js_vulnerabilities_may_2025.json", "w") as f:
        json.dump(vulnerabilities, f, indent=2)
    print(f"\nFull results saved to js_vulnerabilities_may_2025.json")

if __name__ == "__main__":
    main()