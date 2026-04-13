# 🐍 Automation Scripts

SOC analysts often need to parse logs or pivot data quickly. This folder contains small scripts I've written to handle repetitive tasks that aren't covered by the main SOAR tool.

## ⚙️ Scripts Included
- `ioc_scraper.py`: Extracts all IPs and Hashes from a block of text/log file.
- `virustotal_check.py`: (API Wrapper) Batch checks a list of hashes against VirusTotal.
- `log_cleaner.sh`: Quick bash script to anonymize sensitive usernames from log files before sharing.

## 🛡️ Note on SOAR
In a production environment, **SOAR Playbooks** handle 95% of these actions. These scripts represent the "glue" knowledge required to understand how automation works under the hood.