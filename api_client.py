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




"""
Spamhaus Project API Client
Fetches threat intelligence data from Spamhaus blocklists
"""

import requests
import socket
import json
import os
from datetime import datetime

# Spamhaus API Configuration
SPAMHAUS_API_KEY = os.environ.get("SPAMHAUS_API_KEY", "")
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_DROP_V6_URL = "https://www.spamhaus.org/drop/dropv6.txt"
SPAMHAUS_EBL_URL = "https://www.spamhaus.org/ebl/ebl.txt"
SPAMHAUS_API_URL = "https://apidata.spamhaus.org/api/v1"


def fetch_drop_list():
    """
    Fetch the Spamhaus DROP (Don't Route Or Peer) list.
    This list contains netblocks that are hijacked or leased by spammers/malware operators.
    
    Returns:
        List of IP ranges or None on error
    """
    try:
        response = requests.get(SPAMHAUS_DROP_URL, timeout=30)
        response.raise_for_status()
        
        lines = response.text.strip().split("\n")
        ip_ranges = []
        
        for line in lines:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith(";"):
                continue
            # Extract IP range (first field before any comment)
            ip_range = line.split(";")[0].strip()
            if ip_range:
                ip_ranges.append(ip_range)
        
        return ip_ranges
    except requests.exceptions.RequestException as e:
        print(f"Error fetching DROP list: {e}")
        return None


def fetch_dropv6_list():
    """
    Fetch the Spamhaus DROPv6 (IPv6) list.
    
    Returns:
        List of IPv6 ranges or None on error
    """
    try:
        response = requests.get(SPAMHAUS_DROP_V6_URL, timeout=30)
        response.raise_for_status()
        
        lines = response.text.strip().split("\n")
        ip_ranges = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            ip_range = line.split(";")[0].strip()
            if ip_range:
                ip_ranges.append(ip_range)
        
        return ip_ranges
    except requests.exceptions.RequestException as e:
        print(f"Error fetching DROPv6 list: {e}")
        return None


def fetch_ebl_list():
    """
    Fetch the Spamhaus EBL (Email Block List).
    
    Returns:
        List of IP addresses or None on error
    """
    try:
        response = requests.get(SPAMHAUS_EBL_URL, timeout=30)
        response.raise_for_status()
        
        lines = response.text.strip().split("\n")
        ip_addresses = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            ip_addr = line.split(";")[0].strip()
            if ip_addr:
                ip_addresses.append(ip_addr)
        
        return ip_addresses
    except requests.exceptions.RequestException as e:
        print(f"Error fetching EBL list: {e}")
        return None


def check_ip_in_spamhaus(ip_address, list_type="SBL"):
    """
    Check if an IP is listed in a specific Spamhaus blocklist using the API.
    
    Args:
        ip_address: The IP address to check
        list_type: The blocklist to check (SBL, XBL, PBL, DBL, SBLCSS)
    
    Returns:
        JSON response with listing info or None on error
    """
    if not SPAMHAUS_API_KEY:
        print("Warning: SPAMHAUS_API_KEY not set. Using DNS-based lookup instead.")
        return check_ip_dns(ip_address, list_type)
    
    endpoint = f"{SPAMHAUS_API_URL}/check/{list_type}/{ip_address}"
    params = {"data": "yes"}
    headers = {"Authorization": f"Bearer {SPAMHAUS_API_KEY}"}
    
    try:
        response = requests.get(endpoint, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error checking IP {ip_address}: {e}")
        return None


def check_ip_dns(ip_address, list_type="SBL"):
    """
    Check if an IP is listed using DNS-based lookup (free method).
    
    Args:
        ip_address: The IP address to check
        list_type: The blocklist to check
    
    Returns:
        True if listed, False if not, None on error
    """
    # Reverse the IP address for DNS query
    try:
        reversed_ip = ".".join(reversed(ip_address.split(".")))
        query = f"{reversed_ip}.{list_type.lower()}.dbl.spamhaus.org"
        
        result = socket.resolve(query)
        return result is not None
    except socket.gaierror as e:
        # NXDOMAIN means not listed
        if e.errno == 8:  # DNS name does not exist
            return False
        print(f"DNS lookup error: {e}")
        return None
    except Exception as e:
        print(f"Error checking IP via DNS: {e}")
        return None


def fetch_all_drop_lists():
    """
    Fetch all DROP lists (IPv4 and IPv6).
    
    Returns:
        Dictionary with 'ipv4' and 'ipv6' lists
    """
    result = {
        "ipv4": fetch_drop_list(),
        "ipv6": fetch_dropv6_list()
    }
    return result


def main():
    """Example usage of the Spamhaus API client."""
    
    print("Fetching Spamhaus DROP list...")
    drop_list = fetch_drop_list()
    
    if drop_list:
        print(f"\nFound {len(drop_list)} IPv4 ranges in DROP list:")
        for ip_range in drop_list[:10]:  # Show first 10
            print(f"  - {ip_range}")
        if len(drop_list) > 10:
            print(f"  ... and {len(drop_list) - 10} more")
    else:
        print("No DROP list retrieved or error occurred")
    
    print("\n" + "="*50 + "\n")
    
    print("Fetching Spamhaus DROPv6 list...")
    dropv6_list = fetch_dropv6_list()
    
    if dropv6_list:
        print(f"\nFound {len(dropv6_list)} IPv6 ranges in DROPv6 list:")
        for ip_range in dropv6_list[:10]:  # Show first 10
            print(f"  - {ip_range}")
        if len(dropv6_list) > 10:
            print(f"  ... and {len(dropv6_list) - 10} more")
    else:
        print("No DROPv6 list retrieved or error occurred")
    
    print("\n" + "="*50 + "\n")
    
    print("Fetching Spamhaus EBL list...")
    ebl_list = fetch_ebl_list()
    
    if ebl_list:
        print(f"\nFound {len(ebl_list)} IPs in EBL list:")
        for ip_addr in ebl_list[:10]:  # Show first 10
            print(f"  - {ip_addr}")
        if len(ebl_list) > 10:
            print(f"  ... and {len(ebl_list) - 10} more")
    else:
        print("No EBL list retrieved or error occurred")


if __name__ == "__main__":
    main()