#!/usr/bin/env python3
"""
CVE-2025-5958 Verification Script
Checks multiple official sources to verify CVE existence
"""

import requests
import json
import re
from urllib.parse import quote

def validate_cve_format(cve_id):
    """Validate CVE ID format"""
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id))

def check_mitre_cve(cve_id):
    """Check MITRE CVE database"""
    url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            if "not found" in content or "does not exist" in content:
                return False, "CVE not found in MITRE database"
            elif "reserved" in content:
                return True, "CVE reserved but not published"
            elif "description" in content:
                return True, "CVE found in MITRE database"
        return False, f"HTTP {response.status_code}"
    except Exception as e:
        return False, f"Error accessing MITRE: {str(e)}"

def check_nvd_cve(cve_id):
    """Check National Vulnerability Database"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('totalResults', 0) > 0:
                return True, "CVE found in NVD"
            else:
                return False, "CVE not found in NVD"
        return False, f"HTTP {response.status_code}"
    except Exception as e:
        return False, f"Error accessing NVD: {str(e)}"

def check_cvedetails(cve_id):
    """Check CVE Details database"""
    url = f"https://www.cvedetails.com/cve/{cve_id}/"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text.lower()
            if "not found" in content or "does not exist" in content:
                return False, "CVE not found in CVE Details"
            else:
                return True, "CVE found in CVE Details"
        elif response.status_code == 404:
            return False, "CVE not found (404)"
        return False, f"HTTP {response.status_code}"
    except Exception as e:
        return False, f"Error accessing CVE Details: {str(e)}"

def main():
    cve_id = "CVE-2025-5958"
    
    print(f"🔍 Verifying {cve_id}")
    print("=" * 50)
    
    # Format validation
    print("1. Format Validation:")
    if validate_cve_format(cve_id):
        print("   ✅ CVE format is valid")
    else:
        print("   ❌ CVE format is invalid")
        return
    
    # Check multiple sources
    sources = [
        ("MITRE CVE Database", check_mitre_cve),
        ("National Vulnerability Database", check_nvd_cve),
        ("CVE Details", check_cvedetails)
    ]
    
    results = []
    for source_name, check_func in sources:
        print(f"\n2. Checking {source_name}:")
        try:
            found, message = check_func(cve_id)
            if found:
                print(f"   ✅ {message}")
                results.append(True)
            else:
                print(f"   ❌ {message}")
                results.append(False)
        except Exception as e:
            print(f"   ⚠️  Error: {str(e)}")
            results.append(None)
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 VERIFICATION SUMMARY:")
    
    found_count = sum(1 for r in results if r is True)
    not_found_count = sum(1 for r in results if r is False)
    error_count = sum(1 for r in results if r is None)
    
    if found_count > 0:
        print(f"✅ CVE found in {found_count} source(s)")
        print("🔍 CONCLUSION: CVE appears to be LEGITIMATE")
    elif not_found_count == len([r for r in results if r is not None]):
        print(f"❌ CVE not found in any of {not_found_count} accessible source(s)")
        print("🔍 CONCLUSION: CVE appears to be FABRICATED or not yet published")
    else:
        print("⚠️  Mixed results or errors occurred")
        print("🔍 CONCLUSION: Manual verification required")
    
    if error_count > 0:
        print(f"⚠️  {error_count} source(s) had access errors")

if __name__ == "__main__":
    main()