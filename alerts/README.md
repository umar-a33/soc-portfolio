# 🚨 Alert Investigation Write-Ups

This folder contains detailed case notes from simulated security alerts I've investigated. Each write-up follows the standard **Triage → Enrichment → Containment → Closure** lifecycle.

## 📝 Format for Each Alert
Every `.md` file in this folder follows this structure:
1. **Alert Summary:** What did the SIEM/EDR trigger on?
2. **Investigation Steps:** What queries did I run? What did the SOAR enrichment show?
3. **Verdict:** True Positive / False Positive / Benign True Positive.
4. **Response Actions:** Was a host isolated? Was a user password reset?

## 📁 Example Files
- `phishing-attachment-delivered.md`
- `suspicious-powershell-encoded-command.md`
- `impossible-travel-login.md`