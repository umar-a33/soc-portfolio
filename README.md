# 🛡️ SOC Analyst Toolbelt & Workflow

## 🔧 Core Technologies I Operate

| Category | Tool/Function | How I Use It |
| :--- | :--- | :--- |
| **SIEM** | Splunk / ELK / QRadar | Monitoring dashboards for suspicious events, writing basic search queries, and escalating raw alerts. |
| **SOAR** | Splunk Phantom / Cortex XSOAR | **Case Management:** I pivot from a SIEM alert into a SOAR ticket. The platform automatically enriches IOCs (IPs/Hashes) for me so I don't have to manually open 5 different browser tabs. |
| **EDR** | CrowdStrike / SentinelOne | Investigating process trees on endpoints, isolating suspicious hosts, and retrieving forensic file samples. |
| **Threat Intel** | VirusTotal / AlienVault OTX | Checking the reputation of IP addresses and file hashes (often automated *via* SOAR). |
| **Sandbox** | Any.Run / Joe Sandbox | Detonating suspicious files retrieved from email alerts to observe malicious behavior. |

## 📋 My Standard Playbook Workflow

When an alert fires in the SIEM, here is my repeatable process (enforced via SOAR playbooks):

1.  **Triage:** Verify the alert is not a false positive (e.g., internal scanning).
2.  **Enrichment (Automated):** Let SOAR query **VirusTotal** for the source IP/Hash.
3.  **Endpoint Check:** Pivot to **EDR** to see if the file executed or was blocked.
4.  **Containment:** If malicious, isolate the host network via **EDR**.
5.  **Close & Document:** Update the case notes in **SOAR** for handoff to the next shift.

## 🧠 The SOAR Benefit (TL;DR)
Instead of me manually searching `192.168.x.x` in three different databases, **SOAR** does the lookup instantly and presents the result in the case ticket. This saves me ~5 minutes per alert and ensures I follow the exact same steps as the rest of the team.
