#!/usr/bin/env python3
"""
VirusTotal IOC Checker - Query VT API for Threat Intelligence

This script allows a SOC analyst to quickly check the reputation of an
indicator (file hash, IP, domain, or URL) using the VirusTotal API v3.

Features:
- Supports MD5, SHA1, SHA256 hashes
- Supports IPv4 addresses
- Supports domains and URLs
- Returns a concise summary of detection ratios and key verdicts

Author: Umar Ahmed
Date: April 2026
Version: 1.0
"""

import requests
import argparse
import sys
import json
import base64
from typing import Dict, Any, Optional

# VirusTotal API v3 base URL
VT_API_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalChecker:
    """Handle VirusTotal API queries and format results."""

    def __init__(self, api_key: str, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json"
        })

    def _identify_ioc_type(self, ioc: str) -> str:
        """
        Automatically identify the type of IOC.
        Returns: 'file', 'ip', 'domain', or 'url'
        """
        ioc = ioc.strip()

        # Check for file hash (MD5=32 hex, SHA1=40 hex, SHA256=64 hex)
        if len(ioc) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in ioc):
            return "file"

        # Check for IPv4
        parts = ioc.split(".")
        if len(parts) == 4:
            if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return "ip"

        # Check for URL (contains scheme or common TLD patterns)
        if ioc.startswith(("http://", "https://", "ftp://")):
            return "url"

        # Default to domain
        return "domain"

    def _encode_url(self, url: str) -> str:
        """Encode URL in base64 for VT API (without padding)."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def query(self, ioc: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for the given IOC."""
        ioc_type = self._identify_ioc_type(ioc)

        endpoints = {
            "file": f"/files/{ioc}",
            "ip": f"/ip_addresses/{ioc}",
            "domain": f"/domains/{ioc}",
            "url": f"/urls/{self._encode_url(ioc)}"
        }

        endpoint = endpoints.get(ioc_type)
        if not endpoint:
            print(f"[!] Could not identify IOC type for: {ioc}")
            return None

        url = f"{VT_API_BASE}{endpoint}"
        if self.verbose:
            print(f"[*] Querying {url} (type: {ioc_type})")

        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                print(f"[!] IOC not found in VirusTotal: {ioc}")
                return None
            else:
                print(f"[!] API error: HTTP {response.status_code}")
                if self.verbose:
                    print(f"    Response: {response.text}")
                return None
        except Exception as e:
            print(f"[!] Request failed: {e}")
            return None

    def parse_file_report(self, data: Dict) -> Dict[str, Any]:
        """Parse file hash response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        # Count malicious by checking vendor category
        malicious_vendors = [
            vendor for vendor, res in results.items()
            if res.get("category") == "malicious"
        ]

        return {
            "type": "file",
            "ioc": attrs.get("sha256", attrs.get("sha1", attrs.get("md5", "unknown"))),
            "names": attrs.get("names", [])[:3],  # Top 3 names
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "malicious_vendors": malicious_vendors[:5],
            "first_submission": attrs.get("first_submission_date"),
            "last_analysis": attrs.get("last_analysis_date"),
            "popular_threat_name": attrs.get("popular_threat_classification", {}).get("popular_threat_name", "None")
        }

    def parse_ip_report(self, data: Dict) -> Dict[str, Any]:
        """Parse IP address response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        malicious_vendors = [
            vendor for vendor, res in results.items()
            if res.get("category") == "malicious"
        ]

        return {
            "type": "ip",
            "ioc": attrs.get("ip_address", "unknown"),
            "country": attrs.get("country", "unknown"),
            "as_owner": attrs.get("as_owner", "unknown"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "malicious_vendors": malicious_vendors[:5],
            "last_analysis": attrs.get("last_analysis_date"),
            "reputation": attrs.get("reputation", 0)
        }

    def parse_domain_report(self, data: Dict) -> Dict[str, Any]:
        """Parse domain response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        malicious_vendors = [
            vendor for vendor, res in results.items()
            if res.get("category") == "malicious"
        ]

        return {
            "type": "domain",
            "ioc": attrs.get("domain", "unknown"),
            "categories": attrs.get("categories", {}),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "malicious_vendors": malicious_vendors[:5],
            "last_analysis": attrs.get("last_analysis_date"),
            "reputation": attrs.get("reputation", 0)
        }

    def parse_url_report(self, data: Dict) -> Dict[str, Any]:
        """Parse URL response."""
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        malicious_vendors = [
            vendor for vendor, res in results.items()
            if res.get("category") == "malicious"
        ]

        return {
            "type": "url",
            "ioc": attrs.get("url", "unknown"),
            "title": attrs.get("title", "N/A"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "malicious_vendors": malicious_vendors[:5],
            "last_analysis": attrs.get("last_analysis_date"),
            "outgoing_links": attrs.get("outgoing_links", [])[:3]
        }

    def check(self, ioc: str, json_output: bool = False) -> None:
        """Main check method."""
        data = self.query(ioc)
        if not data:
            return

        ioc_type = self._identify_ioc_type(ioc)

        if ioc_type == "file":
            parsed = self.parse_file_report(data)
        elif ioc_type == "ip":
            parsed = self.parse_ip_report(data)
        elif ioc_type == "domain":
            parsed = self.parse_domain_report(data)
        else:  # url
            parsed = self.parse_url_report(data)

        if json_output:
            print(json.dumps(parsed, indent=2))
        else:
            self._print_human_readable(parsed)

    def _print_human_readable(self, parsed: Dict) -> None:
        """Print a clean human-readable summary."""
        print("\n" + "=" * 50)
        print(f"VirusTotal Report: {parsed['ioc']}")
        print(f"Type: {parsed['type']}")
        print("=" * 50)

        detection_ratio = f"{parsed['malicious']}/{parsed['total_engines']}"
        print(f"Detection Ratio: {detection_ratio}")

        # Verdict based on malicious count
        if parsed['malicious'] > 0:
            print("Verdict: ⚠️  MALICIOUS")
        elif parsed['suspicious'] > 0:
            print("Verdict: ⚠️  SUSPICIOUS")
        else:
            print("Verdict: ✅ CLEAN / UNDETECTED")

        if parsed.get('popular_threat_name') and parsed['popular_threat_name'] != "None":
            print(f"Threat Name: {parsed['popular_threat_name']}")

        if parsed.get('names'):
            print(f"Associated Names: {', '.join(parsed['names'])}")

        if parsed.get('country'):
            print(f"Country: {parsed['country']}")

        if parsed.get('as_owner'):
            print(f"AS Owner: {parsed['as_owner']}")

        if parsed.get('reputation', 0) != 0:
            print(f"Community Reputation: {parsed['reputation']}")

        if parsed.get('malicious_vendors'):
            print(f"Malicious Detections: {', '.join(parsed['malicious_vendors'])}")

        print(f"Last Analysis: {parsed.get('last_analysis', 'Unknown')}")
        print("=" * 50 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Check an IOC (hash, IP, domain, or URL) against VirusTotal API."
    )
    parser.add_argument(
        "ioc",
        help="Indicator to check (file hash, IP address, domain, or URL)"
    )
    parser.add_argument(
        "-k", "--api-key",
        help="VirusTotal API key (or set VT_API_KEY environment variable)"
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output raw JSON instead of human-readable summary"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Get API key from argument or environment
    import os
    api_key = args.api_key or os.environ.get("VT_API_KEY")
    if not api_key:
        print("[!] VirusTotal API key required.")
        print("    Provide via -k argument or set VT_API_KEY environment variable.")
        print("    Get a free API key at: https://www.virustotal.com/gui/join-us")
        sys.exit(1)

    checker = VirusTotalChecker(api_key, verbose=args.verbose)
    checker.check(args.ioc, json_output=args.json)


if __name__ == "__main__":
    main()
