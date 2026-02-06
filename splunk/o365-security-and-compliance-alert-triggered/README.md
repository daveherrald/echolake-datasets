# O365 Security And Compliance Alert Triggered

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies alerts triggered by the Office 365 Security and Compliance Center, indicating potential threats or policy violations. It leverages data from the `o365_management_activity` dataset, focusing on events where the workload is SecurityComplianceCenter and the operation is AlertTriggered. This activity is significant as it highlights security and compliance issues within the O365 environment, which are crucial for maintaining organizational security. If confirmed malicious, these alerts could indicate attempts to breach security policies, leading to unauthorized access, data exfiltration, or other malicious activities.

## MITRE ATT&CK

- T1078.004

## Analytic Stories

- Office 365 Account Takeover

## Data Sources


## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/o365_security_and_compliance_alert_triggered/o365_security_and_compliance_alert_triggered.log


---

*Source: [Splunk Security Content](detections/cloud/o365_security_and_compliance_alert_triggered.yml)*
