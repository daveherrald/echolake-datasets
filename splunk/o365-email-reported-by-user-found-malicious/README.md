# O365 Email Reported By User Found Malicious

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects when an email submitted to Microsoft using the built-in report button in Outlook is found to be malicious. This capability is an enhanced protection feature that can be used within o365 tenants by users to report potentially malicious emails. This correlation looks for any submission that returns a Phish or Malware verdict upon submission.

## MITRE ATT&CK

- T1566.001
- T1566.002

## Analytic Stories

- Spearphishing Attachments
- Suspicious Emails

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_reported_by_user_found_malicious.yml)*
