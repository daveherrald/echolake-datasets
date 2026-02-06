# O365 Advanced Audit Disabled

**Type:** TTP

**Author:** Mauricio Velazco, Michael Haag, Splunk

## Description

The following analytic detects instances where the O365 advanced audit is disabled for a specific user within the Office 365 tenant. It uses O365 audit logs, focusing on events related to audit license changes in AzureActiveDirectory workloads. This activity is significant because the O365 advanced audit provides critical logging and insights into user and administrator activities. Disabling it can blind security teams to potential malicious actions. If confirmed malicious, attackers could operate within the user's mailbox or account with reduced risk of detection, leading to unauthorized data access, data exfiltration, or account compromise.

## MITRE ATT&CK

- T1562.008

## Analytic Stories

- Office 365 Persistence Mechanisms

## Data Sources

- O365 Change user license.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.008/o365_advanced_audit_disabled/o365_advanced_audit_disabled.log


---

*Source: [Splunk Security Content](detections/cloud/o365_advanced_audit_disabled.yml)*
