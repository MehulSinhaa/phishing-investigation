# Phishing Email Investigation & Response

Investigation of real-world phishing emails, performed as a SOC analyst would:
header and sender-authentication analysis, link and attachment triage,
IOC extraction and an incident report for each case.

## Tools
Email header analysis · SPF / DKIM / DMARC · VirusTotal · urlscan.io · CyberChef · Python

## Method
1. Collect the raw email (.eml) safely, never opening links or attachments.
2. Analyse headers: sender, Return-Path, Reply-To, Received chain, SPF/DKIM/DMARC results.
3. Extract and defang URLs, check their reputation without visiting them.
4. Hash attachments (SHA-256) and check the hash, without opening the file.
5. Give a verdict, list the IOCs and recommend actions.

## Cases
| # | Lure | Verdict | Key finding | Report |
|---|------|---------|-------------|--------|
| 1 | | | | [report](reports/case-01.md) |

## Key takeaways
_(write 3–5 lessons learned at the end)_

## Safety
Samples are stored only as raw .eml files. No link was clicked and no attachment was opened.
All URLs and domains in reports are defanged (hxxp, example[.]com).
