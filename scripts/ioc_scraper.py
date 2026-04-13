#!/usr/bin/env python3
"""
IOC Scraper - Collect Indicators of Compromise from Public Feeds

This script fetches recent IOCs (IPs, domains, URLs, file hashes) from open
threat intelligence sources and outputs them in a structured format.

Sources used:
- URLhaus (malicious URLs)
- MalwareBazaar (malware samples and associated IOCs)
- AlienVault OTX (community pulses)
- Blocklist.de (recent attacker IPs)

Author: Umar Ahmed
Date: April 2026
Version: 1.0
"""

import requests
import json
import csv
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Set

# Suppress SSL warnings if needed (use cautiously)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IOCScraper:
    """Collect IOCs from multiple open threat feeds."""

    def __init__(self, output_format: str = "csv", verbose: bool = False):
        self.output_format = output_format
        self.verbose = verbose
        self.iocs: Dict[str, Set[str]] = {
            "ip": set(),
            "domain": set(),
            "url": set(),
            "hash_md5": set(),
            "hash_sha256": set(),
        }
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "IOC-Scraper/1.0 (SOC Analyst Lab)"
        })

    def log(self, message: str) -> None:
        """Print verbose messages if enabled."""
        if self.verbose:
            print(f"[*] {message}")

    def fetch_urlhaus_recent(self, limit: int = 100) -> None:
        """
        Fetch recent malicious URLs from URLhaus.
        API docs: https://urlhaus-api.abuse.ch/
        """
        self.log("Fetching recent URLs from URLhaus...")
        url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    for entry in data.get("urls", [])[:limit]:
                        url_str = entry.get("url")
                        if url_str:
                            self.iocs["url"].add(url_str)
                        # Also extract domain from URL
                        domain = self.extract_domain(url_str)
                        if domain:
                            self.iocs["domain"].add(domain)
                    self.log(f"  -> Added {len(data.get('urls', []))} URLs")
                else:
                    self.log(f"  -> URLhaus query failed: {data.get('query_status')}")
            else:
                self.log(f"  -> HTTP {response.status_code} from URLhaus")
        except Exception as e:
            self.log(f"  -> Error fetching URLhaus: {e}")

    def fetch_malwarebazaar_recent(self, limit: int = 100) -> None:
        """
        Fetch recent malware samples from MalwareBazaar and extract hashes.
        API docs: https://bazaar.abuse.ch/api/
        """
        self.log("Fetching recent samples from MalwareBazaar...")
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {"query": "get_recent", "selector": "time", "limit": limit}
        try:
            response = self.session.post(url, data=data, timeout=30)
            if response.status_code == 200:
                resp_json = response.json()
                if resp_json.get("query_status") == "ok":
                    for entry in resp_json.get("data", []):
                        sha256 = entry.get("sha256_hash")
                        md5 = entry.get("md5_hash")
                        if sha256:
                            self.iocs["hash_sha256"].add(sha256)
                        if md5:
                            self.iocs["hash_md5"].add(md5)
                    self.log(f"  -> Added {len(resp_json.get('data', []))} sample hashes")
                else:
                    self.log(f"  -> MalwareBazaar query failed: {resp_json.get('query_status')}")
            else:
                self.log(f"  -> HTTP {response.status_code} from MalwareBazaar")
        except Exception as e:
            self.log(f"  -> Error fetching MalwareBazaar: {e}")

    def fetch_blocklist_de(self) -> None:
        """
        Fetch recent attacker IPs from blocklist.de.
        Source: https://lists.blocklist.de/lists/all.txt
        """
        self.log("Fetching attacker IPs from blocklist.de...")
        url = "https://lists.blocklist.de/lists/all.txt"
        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                ips = response.text.strip().split("\n")
                for ip in ips:
                    ip = ip.strip()
                    if ip and not ip.startswith("#"):
                        self.iocs["ip"].add(ip)
                self.log(f"  -> Added {len(ips)} IP addresses")
            else:
                self.log(f"  -> HTTP {response.status_code} from blocklist.de")
        except Exception as e:
            self.log(f"  -> Error fetching blocklist.de: {e}")

    def fetch_alienvault_otx_pulses(self, limit: int = 5) -> None:
        """
        Fetch recent IOCs from AlienVault OTX community pulses.
        Note: Requires an API key for higher limits. Free tier works.
        """
        self.log("Fetching recent pulses from AlienVault OTX...")
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
        params = {"limit": limit}
        try:
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for pulse in data.get("results", []):
                    for indicator in pulse.get("indicators", []):
                        ioc_type = indicator.get("type")
                        ioc_value = indicator.get("indicator")
                        if ioc_type == "IPv4":
                            self.iocs["ip"].add(ioc_value)
                        elif ioc_type in ["domain", "hostname"]:
                            self.iocs["domain"].add(ioc_value)
                        elif ioc_type == "URL":
                            self.iocs["url"].add(ioc_value)
                        elif ioc_type == "FileHash-MD5":
                            self.iocs["hash_md5"].add(ioc_value)
                        elif ioc_type == "FileHash-SHA256":
                            self.iocs["hash_sha256"].add(ioc_value)
                self.log(f"  -> Processed {len(data.get('results', []))} pulses")
            else:
                self.log(f"  -> HTTP {response.status_code} from AlienVault OTX")
        except Exception as e:
            self.log(f"  -> Error fetching AlienVault OTX: {e}")

    @staticmethod
    def extract_domain(url: str) -> str:
        """Extract domain from URL, removing scheme and path."""
        if not url:
            return ""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc
            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]
            return domain.lower()
        except Exception:
            return ""

    def deduplicate(self) -> None:
        """Remove duplicates across categories (e.g., IPs already in domain list)."""
        # Already using sets, but ensure consistency
        for key in self.iocs:
            self.iocs[key] = set(self.iocs[key])

    def collect_all(self, limit: int = 100) -> None:
        """Run all feed fetchers."""
        self.log("Starting IOC collection...")
        self.fetch_urlhaus_recent(limit)
        self.fetch_malwarebazaar_recent(limit)
        self.fetch_blocklist_de()
        self.fetch_alienvault_otx_pulses(limit=min(limit, 20))  # OTX pulse limit
        self.deduplicate()
        self.log("Collection complete.")

    def output_csv(self, filename: str) -> None:
        """Write IOCs to a CSV file with type and value columns."""
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["type", "value", "source_timestamp"])
            timestamp = datetime.utcnow().isoformat() + "Z"
            for ioc_type, values in self.iocs.items():
                for value in sorted(values):
                    writer.writerow([ioc_type, value, timestamp])
        print(f"[+] CSV output written to {filename}")

    def output_json(self, filename: str) -> None:
        """Write IOCs to a JSON file."""
        output = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "counts": {k: len(v) for k, v in self.iocs.items()},
            "iocs": {k: sorted(list(v)) for k, v in self.iocs.items()}
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"[+] JSON output written to {filename}")

    def output_text(self, filename: str) -> None:
        """Write IOCs to a plain text file, one per line with type prefix."""
        with open(filename, "w", encoding="utf-8") as f:
            for ioc_type, values in self.iocs.items():
                for value in sorted(values):
                    f.write(f"{ioc_type}:{value}\n")
        print(f"[+] Text output written to {filename}")

    def output_console(self) -> None:
        """Print summary to console."""
        print("\n[+] IOC Collection Summary")
        print("-" * 40)
        for ioc_type, values in self.iocs.items():
            print(f"  {ioc_type}: {len(values)} indicators")
        print("-" * 40)

    def save(self, filename: str = None) -> None:
        """Save results in the configured output format."""
        if not filename:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            ext = self.output_format
            if ext == "csv":
                filename = f"iocs_{timestamp}.csv"
            elif ext == "json":
                filename = f"iocs_{timestamp}.json"
            else:
                filename = f"iocs_{timestamp}.txt"

        if self.output_format == "csv":
            self.output_csv(filename)
        elif self.output_format == "json":
            self.output_json(filename)
        else:
            self.output_text(filename)


def main():
    parser = argparse.ArgumentParser(
        description="Collect IOCs from public threat intelligence feeds."
    )
    parser.add_argument(
        "-o", "--output",
        choices=["csv", "json", "text"],
        default="csv",
        help="Output format (default: csv)"
    )
    parser.add_argument(
        "-f", "--file",
        help="Output filename (optional, auto-generated if not provided)"
    )
    parser.add_argument(
        "-l", "--limit",
        type=int,
        default=100,
        help="Maximum number of entries to fetch from each API (default: 100)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--console",
        action="store_true",
        help="Print summary to console after saving"
    )

    args = parser.parse_args()

    scraper = IOCScraper(output_format=args.output, verbose=args.verbose)
    scraper.collect_all(limit=args.limit)

    scraper.save(filename=args.file)

    if args.console:
        scraper.output_console()


if __name__ == "__main__":
    main()
