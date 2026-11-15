# Case XX – <short title, e.g. "Fake Microsoft 365 password expiry">

**Date analysed:** YYYY-MM-DD   **Analyst:** Mehul Sinha
**Verdict:** Malicious / Suspicious / Benign   **Severity:** High / Medium / Low

## 1. Summary
2–3 sentences: what the email pretends to be, what it wants the victim to do, and your verdict.

## 2. Header analysis
| Field | Value | Observation |
|---|---|---|
| From | | Display name vs real address? |
| Reply-To | | Different from From? |
| Return-Path | | Matches the From domain? |
| Subject | | Urgency / fear / reward? |
| Date | | |
| Originating IP (first Received) | | Reputation (AbuseIPDB / VirusTotal) |
| Message-ID | | Domain matches sender? |

### Authentication results
| Check | Result | Meaning |
|---|---|---|
| SPF | pass / fail / softfail / none | Was the sending server allowed for that domain? |
| DKIM | pass / fail / none | Was the message signed by the domain? |
| DMARC | pass / fail / none | Does the visible From domain align with SPF/DKIM? |

## 3. Body and social engineering
- Lure used (fake invoice, password expiry, parcel, prize…)
- Red flags (urgency, spelling, generic greeting, mismatched branding)

## 4. URLs (defanged)
| URL | Displayed text | VirusTotal | urlscan.io | Notes |
|---|---|---|---|---|
| hxxps://example[.]com/login | "Verify now" | x/9x engines | screenshot | Credential-harvesting page? |

## 5. Attachments
| File name | SHA-256 | VirusTotal | Notes |
|---|---|---|---|
| | | | Not opened |

## 6. Indicators of Compromise (IOCs)
- Sender address:
- Sending domain / IP:
- URLs / domains:
- File hashes:

## 7. MITRE ATT&CK
- T1566.001 Phishing: Spearphishing Attachment
- T1566.002 Phishing: Spearphishing Link
(keep only what applies)

## 8. Recommended actions
- Block sender domain / IP / URLs at the email gateway and proxy
- Search mailboxes for other copies (same subject / sender) and remove them
- If a user clicked: reset password, revoke sessions, check sign-in logs
- Report the URL (e.g. to Google Safe Browsing / phishing.report)

## 9. Evidence
Screenshots in `../screenshots/case-XX-*.png`
