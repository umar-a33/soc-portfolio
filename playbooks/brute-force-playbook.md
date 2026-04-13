# Brute Force Alert Triage Playbook

**Version:** 1.0  
**Owner:** SOC Team  
**Last Updated:** April 2026  
**Classification:** Internal Use Only

---

## Purpose

This playbook provides a standard process for investigating alerts related to potential brute force attacks against user accounts, services, or authentication endpoints. It is designed for Level 1 SOC Analysts and aims to ensure rapid identification of genuine threats and appropriate escalation.

---

## Scope

This playbook covers alerts generated from:

- Multiple failed login attempts (Windows Event ID 4625)
- Account lockouts (Windows Event ID 4740)
- Azure AD / Entra ID risky sign-in alerts (impossible travel, atypical location, password spray)
- VPN or MFA fatigue alerts (repeated push notifications)
- RDP or SSH brute force attempts from external IPs

---

## Triage Phase (First 10 Minutes)

### Step 1: Review the Alert Summary

Open the alert in your SIEM. Capture the following baseline information immediately:

| Field | What to Look For |
| :--- | :--- |
| **Target Account** | Which user account is under attack? (Note if it's a privileged account) |
| **Source IP** | Where are the attempts coming from? Single IP or distributed? |
| **Failure Count** | How many failed attempts? Over what timeframe? |
| **Authentication Method** | Interactive logon, RDP, OWA, VPN, Azure AD? |
| **Outcome** | Did any attempt succeed? (Look for Event ID 4624 near the failures) |
| **Timeframe** | Is this ongoing or historical? |

### Step 2: Quick Risk Triage

Ask these questions to prioritise:

| Question | Low Concern | High Concern |
| :--- | :--- | :--- |
| **Is the account privileged?** | Standard user | Domain Admin, Finance, HR, IT |
| **Did any login succeed?** | No successes | Yes, followed by 4624 |
| **Is the source IP known?** | Internal RFC1918 or company VPN range | Foreign country, TOR exit node, VPS hosting |
| **Is it a password spray?** | No—same account repeatedly | Yes—many accounts, one or two attempts each |
| **Is MFA enabled for the account?** | Yes, and no MFA fatigue observed | No, or MFA prompts being accepted |

If **two or more** high-concern flags are present, escalate urgency.

### Step 3: Document the Alert

Create a case with:

- Target account(s)
- Source IP(s)
- Number of failures and timeframe
- Authentication source (hostname, service)
- Initial risk assessment

---

## Analysis Phase

### 1. Verify the Source of the Attempts

#### Internal vs External
- **Internal IP (10.x.x.x, 172.16.x.x, 192.168.x.x):** Could be a misconfigured service, script, or user with a stuck session. Check the source hostname.
- **External IP:** Treat as higher risk. Check reputation immediately.

#### IP Reputation Check
Submit the source IP to:
- **VirusTotal**
- **AbuseIPDB**
- **Shodan** (to see if it's a known VPS or proxy)

Red flags:
- Reported for SSH/RDP brute force in the last 30 days.
- Geolocation inconsistent with user's normal location.
- Hosting provider (DigitalOcean, AWS, Azure, OVH) with no business reason.

### 2. Analyse the Failure Pattern

#### Classic Brute Force (Single Account)
- Many failures against **one** account.
- Often rapid-fire attempts.
- May trigger account lockout (Event ID 4740).

**What to do:**
- Check if the user is on leave or outside working hours.
- Review any successful logins around the failures.
- If source is external and unknown, block the IP and consider disabling the account temporarily.

#### Password Spray (Multiple Accounts)
- One or two failures per account, across **many** accounts.
- Source IP often consistent.
- Attackers try common passwords (e.g., `Summer2024!`, `Password1`, `CompanyName123`).

**What to do:**
- This is a **high-priority threat**—escalate immediately.
- Identify the password being attempted (if logs show it—some do).
- Force password reset for any account that had a successful login from that IP in the same window.

#### MFA Fatigue / Push Bombing
- User reports multiple unexpected MFA prompts.
- Attacker already has valid credentials and is trying to wear down the user into approving.

**What to do:**
- Advise user **never** to approve unexpected MFA prompts.
- Reset the user's password immediately.
- Revoke existing sessions in Azure AD / Entra ID.
- Check for unusual sign-in locations in Azure AD logs.

### 3. Check for Successful Logins

This is the most critical step. A successful login after a brute force attempt means the attacker likely has access.

#### Windows Event Logs
- Search for **Event ID 4624** (successful logon) from the same source IP or around the same timeframe for the target account.
- Note the **Logon Type**:
  - **Type 3:** Network logon (SMB, shared folder)
  - **Type 10:** RemoteInteractive (RDP)
  - **Type 2:** Interactive (console)

#### Azure AD / Entra ID Logs
- Check **Sign-in logs** for the user.
- Filter by the suspicious IP address.
- Look for **"Success"** status.
- Note any **Conditional Access** policy that may have blocked the attempt.

### 4. Review the Affected Account

| Check | How to Verify |
| :--- | :--- |
| **Is the account active?** | Check AD or Azure AD for disabled status. |
| **Is MFA enforced?** | Confirm MFA registration and enforcement. |
| **What is the user's role?** | Review group memberships for privileged access. |
| **Any recent password changes?** | Check `pwdLastSet` attribute. |
| **Is the user on holiday?** | Check calendar or ask manager. |

### 5. Look for Lateral Movement Indicators

If a successful login occurred, search for follow-on activity from that session:

- New outbound RDP or SMB connections from the host the user logged into.
- Unusual process execution (refer to Suspicious Process Playbook).
- Creation of new user accounts or addition to privileged groups.

---

## Verdict & Actions

### False Positive (Benign Activity)

**Criteria:**
- Source IP is internal and traced to a known service account or script.
- User confirms they were testing a new password or had a stuck mobile device.
- Failures are infrequent and no success observed.
- IP reputation is clean and geolocation matches user.

**Action:**
- Document the rationale.
- Close the alert.
- If a recurring issue (e.g., service account with expired password), escalate to IT for remediation.

### Low Confidence Suspicious (Monitor)

**Criteria:**
- External IP with no clear reputation.
- Failures under 50 and spread over several hours.
- No successful login.
- Standard user account, MFA enabled.

**Action:**
- Add source IP to a watchlist for 24 hours.
- Advise user to change password if they suspect anything.
- Close case with recommendation to monitor.

### Confirmed Attempt (No Success)

**Criteria:**
- High failure count from a known malicious IP or suspicious geolocation.
- Password spray pattern observed.
- MFA fatigue reported but user denied all prompts.

**Action:**
1. Block source IP at firewall or Conditional Access policy.
2. Force password reset for any targeted accounts as a precaution.
3. Add IP to threat intelligence feed.
4. Escalate to **Level 2** for wider review of authentication logs.
5. If password spray, search logs for the same IP across the entire tenant.

### Confirmed Compromise (Successful Login)

**Criteria:**
- One or more successful logins following failed attempts.
- Logon from unusual location or TOR exit node.
- User confirms they did not approve MFA prompt.
- Post-login activity is suspicious.

**Action:**
1. **Immediate escalation to Incident Response.**
2. Disable the compromised account.
3. Reset password and revoke all sessions.
4. Isolate any host(s) the attacker logged into.
5. Begin scoping activity: what did the attacker access or modify?
6. Treat as a **Priority 1 incident**.

---

## Escalation Criteria

Escalate to **Level 2 SOC Analyst** if:

- Password spray detected.
- Source IP is a known TOR exit node or associated with a threat actor.
- Targeted account is a Domain Admin or equivalent.
- MFA fatigue reported and user is unsure if they approved.
- Multiple accounts locked out simultaneously from the same source.

Escalate to **Incident Response** if:

- Any successful login from an untrusted source.
- Evidence of lateral movement or data access.
- Credential dumping or persistence activity observed post-login.

---

## Post-Incident Documentation

Ensure the case file contains:

- [ ] Target account(s) and source IP(s) documented.
- [ ] Timeline of failed and successful attempts.
- [ ] IP reputation check results.
- [ ] Actions taken (blocks applied, password resets, account disablement).
- [ ] Verdict and rationale.
- [ ] Any IOCs generated (malicious IPs, user agent strings).

---

## MITRE ATT&CK Techniques (Reference)

| Technique ID | Name | Relevance |
| :--- | :--- | :--- |
| **T1110** | Brute Force | Core technique—password guessing, credential stuffing |
| **T1110.003** | Password Spraying | Low-and-slow attacks against many accounts |
| **T1110.004** | Credential Stuffing | Using breached credentials from other services |
| **T1078** | Valid Accounts | Attacker uses successfully guessed credentials |
| **T1621** | Multi-Factor Authentication Request Generation | MFA fatigue / push bombing |

---

## Useful Tools & Resources

| Tool | Purpose | Link |
| :--- | :--- | :--- |
| **VirusTotal** | IP and URL reputation | virustotal.com |
| **AbuseIPDB** | Community-driven IP reputation | abuseipdb.com |
| **Shodan** | IP intelligence (hosting provider, open ports) | shodan.io |
| **TOR Exit Node List** | Check if IP is a TOR exit node | check.torproject.org/exit-addresses |
| **Azure AD Sign-in Logs** | Detailed authentication telemetry | portal.azure.com |
| **CyberChef** | Log parsing and data manipulation | gchq.github.io/CyberChef |

---

## Revision History

| Version | Date | Author | Changes |
| :--- | :--- | :--- | :--- |
| 1.0 | April 2026 | Umar Ahmed | Initial creation |
