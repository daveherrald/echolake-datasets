# O365 Email New Inbox Rule Created

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic identifies the creation of new email inbox rules in an Office 365 environment. It detects events logged under New-InboxRule and Set-InboxRule operations within the o365_management_activity data source, focusing on parameters that may indicate mail forwarding, removal, or obfuscation. Inbox rule creation is a typical end-user activity however attackers also leverage this technique for multiple reasons.

## MITRE ATT&CK

- T1114.003
- T1564.008

## Analytic Stories

- Office 365 Collection Techniques

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_suspect_email_actions/o365_exchange_suspect_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_new_inbox_rule_created.yml)*
