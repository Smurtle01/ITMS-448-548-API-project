# api_client.py
#import pandas as pd
#import numpy as np

# Getters for all the API requests for the data we will analyse
#def get_dataset_1():
#    return pd.DataFrame({
#        "time": range(50),
#        "value": np.random.randint(0, 100, 50)
#    })

#def get_dataset_2():
#    return pd.DataFrame({
#        "category": ["A","B","C","D"],
#        "count": [10, 25, 15, 30]
#    })

#def get_dataset_3():
#    return pd.DataFrame({
#        "x": np.random.randn(100),
#        "y": np.random.randn(100)
#    })

#def get_dataset_4():
#    return pd.DataFrame({
#        "date": pd.date_range("2024-01-01", periods=30),
#        "sales": np.random.randint(100, 500, 30)
#    })
"""
National Vulnerability Database (NVD) API Integration
Fetches vulnerability data from the NVD API
"""

import requests
import json
from datetime import datetime


def fetch_nvd_vulnerabilities(cve_id=None, keyword_search=None, limit=10):
    """
    Fetch vulnerability data from the National Vulnerability Database (NVD) API.
    
    Args:
        cve_id: Specific CVE ID to search for (e.g., 'CVE-2024-1234')
        keyword_search: Keyword to search in vulnerability descriptions
        limit: Maximum number of results to return (default: 10)
    
    Returns:
        List of vulnerability data dictionaries
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    params = {
        "resultsPerPage": limit
    }
    
    # Add CVE ID parameter if provided
    if cve_id:
        params["cveId"] = cve_id
    
    # Add keyword search parameter if provided
    if keyword_search:
        params["keywordSearch"] = keyword_search
    
    try:
        response = requests.get(base_url, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        results = []
        for vuln in vulnerabilities:
            cve_item = vuln.get("cve", {})
            
            result = {
                "id": cve_item.get("id"),
                "description": cve_item.get("descriptions", [{}])[0].get("value", "No description available"),
                "published": cve_item.get("published"),
                "last_modified": cve_item.get("lastModified"),
                "severity": get_severity(cve_item),
                "cvss_score": get_cvss_score(cve_item),
                "references": [ref.get("url") for ref in cve_item.get("references", [])[:5]]
            }
            results.append(result)
        
        return results
        
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse response: {str(e)}"}


def get_severity(cve_item):
    """Extract severity information from CVE item."""
    metrics = cve_item.get("metrics", {})
    
    # Try CVSS v3.1 first
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        return cvss_v31[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
    
    # Try CVSS v3.0
    cvss_v30 = metrics.get("cvssMetricV30", [])
    if cvss_v30:
        return cvss_v30[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
    
    # Try CVSS v2
    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2:
        return cvss_v2[0].get("baseSeverity", "UNKNOWN")
    
    return "UNKNOWN"


def get_cvss_score(cve_item):
    """Extract CVSS score from CVE item."""
    metrics = cve_item.get("metrics", {})
    
    # Try CVSS v3.1 first
    cvss_v31 = metrics.get("cvssMetricV31", [])
    if cvss_v31:
        return cvss_v31[0].get("cvssData", {}).get("baseScore", "N/A")
    
    # Try CVSS v3.0
    cvss_v30 = metrics.get("cvssMetricV30", [])
    if cvss_v30:
        return cvss_v30[0].get("cvssData", {}).get("baseScore", "N/A")
    
    # Try CVSS v2
    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2:
        return cvss_v2[0].get("cvssData", {}).get("baseScore", "N/A")
    
    return "N/A"


def display_vulnerabilities(vulnerabilities):
    """Display vulnerability data in a formatted way."""
    if isinstance(vulnerabilities, dict) and "error" in vulnerabilities:
        print(f"Error: {vulnerabilities['error']}")
        return
    
    if not vulnerabilities:
        print("No vulnerabilities found.")
        return
    
    print(f"\nFound {len(vulnerabilities)} vulnerability(ies):\n")
    print("=" * 80)
    
    for vuln in vulnerabilities:
        print(f"CVE ID: {vuln['id']}")
        print(f"Severity: {vuln['severity']} | CVSS Score: {vuln['cvss_score']}")
        print(f"Published: {vuln['published']}")
        print(f"Description: {vuln['description'][:200]}...")
        print("-" * 80)


def main():
    """Main function to demonstrate NVD API usage."""
    print("National Vulnerability Database (NVD) API Client")
    print("=" * 50)
    
    # Example 1: Search for a specific CVE
    print("\n1. Searching for specific CVE: CVE-2024-3094")
    results = fetch_nvd_vulnerabilities(cve_id="CVE-2024-3094")
    display_vulnerabilities(results)
    
    # Example 2: Search by keyword
    print("\n2. Searching for 'ransomware' vulnerabilities...")
    results = fetch_nvd_vulnerabilities(keyword_search="ransomware", limit=5)
    display_vulnerabilities(results)


if __name__ == "__main__":
    main()