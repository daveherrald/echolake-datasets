# O365 BEC Email Hiding Rule Created

**Type:** TTP

**Author:** 0xC0FFEEEE, Github Community

## Description

This analytic detects mailbox rule creation, a common technique used in Business Email Compromise. It uses a scoring mechanism to identify a combination of attributes often featured in mailbox rules created by attackers. This may indicate that an attacker has gained access to the account.

## MITRE ATT&CK

- T1564.008

## Analytic Stories

- Office 365 Account Takeover

## Data Sources


## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1564.008/o365/o365_suspicious_mailbox_rule.log


---

*Source: [Splunk Security Content](detections/cloud/o365_bec_email_hiding_rule_created.yml)*
