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
| 2 | Fake Leroy Merlin "reward" (French) | Malicious | Google-hosted redirector only works with tracking data; sends victims to a bare IP that public reports link to a scam traffic distribution system | [report](reports/case-02.md) |
| 3 | Fake Netflix "payment declined" | Malicious | Same campaign and redirector as case 01; SPF passed because a real company's SPF record allows any OVH server; TinyURL hides a bare IP | [report](reports/case-03.md) |
| 4 | Fake UnitedHealthcare "free dental kit" | Malicious | Sent from the same server as case 03 on the same day; new Return-Path domain registered in April 2026 with an SPF rule allowing any OVH server | [report](reports/case-04.md) |

## Key takeaways
at the end...

## Safety
Samples are stored only as raw .eml files. No link was clicked and no attachment was opened.
All URLs and domains in reports are defanged (hxxp, example[.]com).

