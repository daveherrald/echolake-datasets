# O365 Email Transport Rule Changed

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when a user with sufficient access to Exchange Online alters the mail flow/transport rule configuration of the organization. Transport rules are a set of rules that can be used by attackers to modify or delete emails based on specific conditions, this activity could indicate an attacker hiding or exfiltrated data.

## MITRE ATT&CK

- T1114.003
- T1564.008

## Analytic Stories

- Data Exfiltration
- Office 365 Account Takeover

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.003/transport_rule_change/transport_rule_change.log


---

*Source: [Splunk Security Content](detections/cloud/o365_email_transport_rule_changed.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
