import requests
import json
from datetime import datetime

def search_go_vulnerabilities():
    # Define the API endpoint
    url = "https://www.tenable.com/cve/api/v2/search"
    
    # Define headers
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    # Define the search parameters
    # We'll search for "golang" in the text field
    payload = {
        "searchType": "or",
        "page": 0,
        "size": 10,
        "sortField": "published_date",
        "sortDir": "desc",
        "filters": {
            "text": ["golang"]
        }
    }
    
    try:
        # Make the request
        response = requests.post(url, headers=headers, json=payload)
        
        # Print status code
        print(f"Status code: {response.status_code}")
        
        # Check if successful
        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()
            return data
        else:
            print(f"Error response: {response.text[:500]}")
            return None
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return None

# Execute the search
result = search_go_vulnerabilities()

# Process and display the results
if result:
    vulnerabilities = result.get('vulnerabilities', [])
    total_count = result.get('totalCount', 0)
    
    print(f"\nTotal Go vulnerabilities found: {total_count}")
    
    if vulnerabilities:
        print("\n10 Most Recent Go Vulnerabilities:\n")
        for i, vuln in enumerate(vulnerabilities[:10], 1):
            cve_id = vuln.get('cve', {}).get('id', 'N/A')
            description = vuln.get('description', 'No description available')
            
            # Get published date
            published_date = vuln.get('published_date', 'N/A')
            if published_date != 'N/A':
                try:
                    # Convert timestamp to readable date
                    published_date = datetime.fromtimestamp(published_date/1000).strftime('%Y-%m-%d')
                except:
                    pass
            
            # Get CVSS score
            cvss_score = vuln.get('cvss', {}).get('score', 'N/A')
            
            # Get affected software
            affected_software = []
            for product in vuln.get('products', []):
                name = product.get('name', '')
                if name:
                    affected_software.append(name)
            
            # Print the vulnerability information
            print(f"{i}. {cve_id} (CVSS: {cvss_score}) - Published: {published_date}")
            print(f"   Description: {description[:200]}..." if len(description) > 200 else f"   Description: {description}")
            if affected_software:
                print(f"   Affected Software: {', '.join(affected_software[:5])}" + 
                      (f" and {len(affected_software) - 5} more..." if len(affected_software) > 5 else ""))
            print()
    else:
        print("No vulnerabilities found.")
else:
    print("Failed to retrieve vulnerabilities.")