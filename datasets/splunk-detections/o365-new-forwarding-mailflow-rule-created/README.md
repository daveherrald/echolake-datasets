# O365 New Forwarding Mailflow Rule Created

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the creation of new mail flow rules in Office 365 that may redirect or copy emails to unauthorized or external addresses. It leverages Office 365 Management Activity logs, specifically querying for the "New-TransportRule" operation and parameters like "BlindCopyTo", "CopyTo", and "RedirectMessageTo". This activity is significant as it can indicate potential data exfiltration or unauthorized access to sensitive information. If confirmed malicious, attackers could intercept or redirect email communications, leading to data breaches or information leakage.

## MITRE ATT&CK

- T1114

## Analytic Stories

- Office 365 Collection Techniques

## Data Sources


## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114/o365_new_forwarding_mailflow_rule_created/o365_new_forwarding_mailflow_rule_created.log


---

*Source: [Splunk Security Content](detections/cloud/o365_new_forwarding_mailflow_rule_created.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
