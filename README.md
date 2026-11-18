# Phishing Email Investigation & Response

Investigation of real-world phishing emails, performed as a SOC analyst would:
header and sender-authentication analysis, link and attachment triage,
IOC extraction and an incident report for each case.

## Tools
Email header analysis · SPF / DKIM / DMARC · VirusTotal · urlscan.io · AbuseIPDB · curl · CyberChef · Python

## Method
1. Collect the raw email (.eml) safely, never opening links or attachments.
2. Analyse headers: sender, Return-Path, Reply-To, Received chain, SPF/DKIM/DMARC results.
3. Extract and defang URLs, check their reputation without visiting them.
4. Hash attachments (SHA-256) and check the hash, without opening the file.
5. Give a verdict, list the IOCs and recommend actions.

## Cases
| # | Lure | Verdict | Key finding | Report |
|---|------|---------|-------------|--------|
| 1 | Fake "account locked" cloud-storage warning | Malicious | Link on Google Cloud Storage redirects to a hidden second domain; 2/93 and 0/92 on VirusTotal | [report](reports/case-01.md) |

## Key takeaways
at the end...

## Safety
Samples are stored only as raw .eml files. No link was clicked and no attachment was opened.
All URLs and domains in reports are defanged (hxxp, example[.]com).

