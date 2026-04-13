# Phishing Email Analysis Playbook

**Version:** 1.0  
**Owner:** SOC Team  
**Last Updated:** April 2026  
**Classification:** Internal Use Only

---

## Purpose

This playbook provides a standard process for triaging and investigating user-reported phishing emails. It is designed for Level 1 SOC Analysts and aims to ensure consistent, documented, and timely handling of potential threats.

---

## Scope

This playbook applies to all emails reported via the phishing report button, forwarded to the SOC mailbox, or escalated through the service desk.

---

## Triage Phase (First 15 Minutes)

Upon receiving a reported email, follow these initial steps **before** deep-dive analysis.

### Step 1: Verify the Report
- Check the user's report reason: "Looks suspicious," "Asked for password," "Urgent payment request," etc.
- Confirm the email is still in the user's inbox (if applicable) and has not been deleted or already remediated.

### Step 2: Quick Sanity Check
- **Sender address:** Does the domain look legitimate at a glance? (e.g., `microsfot.com` vs `microsoft.com`)
- **Subject line:** Does it contain urgency triggers? ("Password Expires in 24 Hours," "Invoice Overdue," "Unusual Sign-in")
- **Attachments:** Are there any? (`.html`, `.exe`, `.iso`, `.docm`, `.pdf` with embedded links)

### Step 3: Document the Report
Create a case in the ticketing system (ServiceNow) with the following minimum information:
- **Reported by:** User name and email
- **Sender address:** From header
- **Subject:** Full subject line
- **Date/Time received:** As per email headers
- **Attachments present:** Yes/No, and file types

---

## Analysis Phase

### 1. Email Header Analysis

Extract the full email headers from the reported message. In Outlook, this is **File > Properties > Internet Headers**.

#### Key Headers to Examine

| Header | What to Look For |
| :--- | :--- |
| **Return-Path** | Should match the `From` domain. Mismatch is a red flag. |
| **Received** | Trace the path back. Look for unexpected hops, free email services, or suspicious IPs. |
| **SPF / DKIM / DMARC** | `spf=fail`, `dkim=fail`, or `dmarc=fail` are strong indicators of spoofing. |
| **Reply-To** | If different from `From` and pointing to a free webmail address, treat as suspicious. |
| **X-Originating-IP** | Check the originating IP against threat intelligence (VirusTotal, AbuseIPDB). |

**Header Analysis Checklist:**
- [ ] SPF result: Pass / Fail / SoftFail / Neutral
- [ ] DKIM result: Pass / Fail / None
- [ ] DMARC result: Pass / Fail / None
- [ ] Originating IP reputation checked: Yes / No
- [ ] Return-Path matches From domain: Yes / No

### 2. URL Analysis

If the email contains links, **do not click them** on your primary workstation.

#### Safe URL Inspection Steps
1. Hover over the link (without clicking) to reveal the true destination.
2. Copy the URL and paste into a text file. **Do not** paste directly into a browser.
3. Submit the URL to:
   - [VirusTotal](https://www.virustotal.com)
   - [URLScan.io](https://urlscan.io)
4. Check the domain registration date using a WHOIS lookup. Domains registered in the last 30 days are higher risk.

#### URL Red Flags
- Uses `http://` instead of `https://` (though not definitive on its own).
- Contains misspelled brand names (e.g., `micr0soft.com`, `amaz0n.co.uk`).
- Uses URL shorteners (`bit.ly`, `tinyurl.com`, `ow.ly`). Expand the link using a tool like `urlexpander.net` before analysis.
- Redirects through multiple domains (visible in URLScan results).

### 3. Attachment Analysis

If the email contains an attachment, treat with extreme caution.

#### Safe Handling Procedure
1. **Do not open** the attachment on your host machine.
2. Download the file **only** to an isolated analysis VM (e.g., FlareVM) or submit to a sandbox.
3. Submit the file hash (SHA-256) to VirusTotal.
4. If a sandbox is available, detonate the file and observe behaviour:
   - Network connections made
   - Processes spawned (`powershell.exe`, `cmd.exe`, `wscript.exe`)
   - Registry modifications
   - Files dropped

#### High-Risk Attachment Types
| Extension | Risk Level | Reason |
| :--- | :--- | :--- |
| `.exe`, `.scr`, `.bat`, `.ps1` | Critical | Executable code |
| `.docm`, `.xlsm`, `.pptm` | High | Macros can execute code |
| `.iso`, `.img`, `.vhd` | High | Often used to bypass Mark of the Web |
| `.html`, `.htm` | Medium | Can contain phishing forms or redirects |
| `.pdf` | Medium | Can contain embedded links or JavaScript |

### 4. Content Analysis

Read the email body for social engineering indicators.

| Tactic | Indicators |
| :--- | :--- |
| **Urgency** | "Action required within 24 hours," "Your account will be suspended" |
| **Authority** | Impersonating IT, HR, CEO, or a known supplier |
| **Fear** | "Unusual login detected," "Payment overdue—legal action pending" |
| **Unusual Request** | Asking for gift cards, changing bank details, or bypassing normal process |
| **Grammatical Errors** | Poor spelling, awkward phrasing, inconsistent branding |

---

## Verdict & Actions

Based on your analysis, classify the email into one of the following categories.

### Clean (False Positive)
- SPF/DKIM/DMARC pass.
- Links go to legitimate domains.
- No suspicious attachments.
- Content matches expected business communication.

**Action:**
- Inform the user the email is safe.
- Close the case with notes explaining the verdict.

### Spam / Marketing
- Unsolicited but not malicious.
- No credential harvesting intent.
- Legitimate sender but unwanted.

**Action:**
- Advise user to block sender or unsubscribe.
- Close case.

### Phishing (Credential Harvesting)
- Links to fake login page.
- SPF/DKIM/DMARC may show failures.
- Domain recently registered or lookalike.

**Action:**
1. Block the sender domain/email address in email gateway.
2. Submit URLs to blocklist.
3. Search mail logs for other recipients of the same email.
4. If user entered credentials, escalate immediately to **Level 2 for Credential Compromise Playbook**.

### Malware (Attachment-Based)
- Attachment is confirmed or strongly suspected malicious.
- Sandbox shows malicious behaviour.
- VirusTotal has multiple detections.

**Action:**
1. Isolate the affected user's machine (coordinate with IT/Endpoint team).
2. Block file hash in EDR/AV.
3. Delete the email from all recipient inboxes.
4. Escalate to **Level 2 for Malware Incident Response**.

---

## Escalation Criteria

Escalate to **Level 2 SOC Analyst** if:

- User has clicked a link **and** entered credentials.
- User has opened a suspicious attachment.
- The email appears targeted (spear phishing) with specific internal knowledge.
- The sender is impersonating a C-level executive or Finance department.
- You identify a pattern (same email reported by multiple users across the organisation).

---

## Post-Incident Documentation

After closing the case, ensure the following is recorded:

- [ ] Ticket updated with analysis findings.
- [ ] Verdict assigned (Clean / Spam / Phishing / Malware).
- [ ] IOCs recorded (malicious URLs, domains, IPs, file hashes).
- [ ] Any blocks applied (email gateway, firewall, EDR).
- [ ] User communicated with (if applicable).

---

## Useful Tools & Resources

| Tool | Purpose | Link |
| :--- | :--- | :--- |
| **VirusTotal** | URL, file hash, and IP reputation | virustotal.com |
| **URLScan.io** | Safe URL analysis and screenshot | urlscan.io |
| **MXToolbox** | Header analysis, SPF/DKIM/DMARC checks | mxtoolbox.com |
| **AbuseIPDB** | IP reputation | abuseipdb.com |
| **Whois Lookup** | Domain registration info | whois.domaintools.com |
| **CyberChef** | Data decoding, email header parsing | gchq.github.io/CyberChef |

---

## Revision History

| Version | Date | Author | Changes |
| :--- | :--- | :--- | :--- |
| 1.0 | April 2026 | Umar Ahmed | Initial creation |
