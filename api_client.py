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

"""
api_client.py
Reliable public cybersecurity API client for your dashboard project.

Data Sources:
1. NVD CVE API (NIST)
2. CISA Known Exploited Vulnerabilities (KEV)
3. MITRE ATT&CK (public)
4. urlhaus recent malware URLs feed

Install:
pip install requests
"""

import requests
import json
from datetime import datetime

HEADERS = {
    "User-Agent": "CyberThreatDashboard/1.0"
}


# 1. NVD API

def fetch_nvd_vulnerabilities(keyword_search=None, limit=10):
    """
    Fetch CVEs from NVD.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {"resultsPerPage": limit}

    if keyword_search:
        params["keywordSearch"] = keyword_search

    try:
        r = requests.get(url, params=params, headers=HEADERS, timeout=30)
        r.raise_for_status()

        data = r.json()
        vulns = data.get("vulnerabilities", [])

        results = []

        for item in vulns:
            cve = item.get("cve", {})

            results.append({
                "id": cve.get("id", "Unknown"),
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "published": cve.get("published", ""),
                "severity": get_severity(cve),
                "cvss_score": get_score(cve)
            })

        return results

    except Exception as e:
        print("NVD Error:", e)
        return []


def get_severity(cve):
    metrics = cve.get("metrics", {})

    for version in ["cvssMetricV31", "cvssMetricV30"]:
        if version in metrics:
            return metrics[version][0]["cvssData"].get("baseSeverity", "UNKNOWN")

    return "UNKNOWN"


def get_score(cve):
    metrics = cve.get("metrics", {})

    for version in ["cvssMetricV31", "cvssMetricV30"]:
        if version in metrics:
            return metrics[version][0]["cvssData"].get("baseScore", 0)

    return 0


# 2. CISA KEV

def fetch_cisa_kev():
    """
    Known Exploited Vulnerabilities catalog.
    """
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()

        data = r.json()

        return data.get("vulnerabilities", [])

    except Exception as e:
        print("CISA Error:", e)
        return []


# 3. Mitre ATT&CK data

def fetch_mitre_attack():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print("MITRE Error:", e)
        return {}


# 4. URLHaus Malware Feed

def fetch_urlhaus_recent():
    url = "https://urlhaus.abuse.ch/downloads/json_recent/"

    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()

        data = r.json()

        results = []

        # IMPORTANT: iterate through dictionary keys
        for key, entries in data.items():
            for item in entries:
                results.append({
                    "id": key,
                    "url": item.get("url"),
                    "dateadded": item.get("dateadded"),
                    "threat": item.get("threat"),
                    "tags": item.get("tags", [])
                })

        return results

    except Exception as e:
        print("URLHaus Error:", e)
        return []


def main():

    print("Testing APIs...\n")

    nvd = fetch_nvd_vulnerabilities("ransomware", 5)
    print("NVD:", len(nvd))

    kev = fetch_cisa_kev()
    print("CISA KEV:", len(kev))

    otx = fetch_mitre_attack()
    print("OTX Pulses:", len(otx))

    urls = fetch_urlhaus_recent()
    print("URLHaus URLs:", len(urls))


if __name__ == "__main__":
    main()