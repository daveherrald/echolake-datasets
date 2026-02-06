# O365 New Email Forwarding Rule Created

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies the creation of new email forwarding rules in an Office 365 environment. It detects events logged under New-InboxRule and Set-InboxRule operations within the o365_management_activity data source, focusing on parameters like ForwardTo, ForwardAsAttachmentTo, and RedirectTo. This activity is significant as unauthorized email forwarding can lead to data exfiltration and unauthorized access to sensitive information. If confirmed malicious, attackers could intercept and redirect emails, potentially compromising confidential communications and leading to data breaches.

## MITRE ATT&CK

- T1114.003

## Analytic Stories

- Office 365 Collection Techniques

## Data Sources


## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.003/o365_email_forwarding_rule_created/o365_email_forwarding_rule_created.log


---

*Source: [Splunk Security Content](detections/cloud/o365_new_email_forwarding_rule_created.yml)*
