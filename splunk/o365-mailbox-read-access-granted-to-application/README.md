# O365 Mailbox Read Access Granted to Application

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where the Mail.Read Graph API permissions are granted to an application registration within an Office 365 tenant. It leverages O365 audit logs, specifically events related to changes in application permissions within the AzureActiveDirectory workload. This activity is significant because the Mail.Read permission allows applications to access and read all emails within a user's mailbox, which often contain sensitive or confidential information. If confirmed malicious, this could lead to data exfiltration, spear-phishing attacks, or further compromise based on the information gathered from the emails.

## MITRE ATT&CK

- T1098.003
- T1114.002

## Analytic Stories

- Office 365 Persistence Mechanisms

## Data Sources

- O365 Update application.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/o365_grant_mail_read/o365_grant_mail_read.log


---

*Source: [Splunk Security Content](detections/cloud/o365_mailbox_read_access_granted_to_application.yml)*
