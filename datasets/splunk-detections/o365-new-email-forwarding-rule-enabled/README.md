# O365 New Email Forwarding Rule Enabled

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying the creation of new email forwarding rules in an Office 365 environment via the UpdateInboxRules operation. It leverages Office 365 management activity events to detect rules that forward emails to external recipients by examining the OperationProperties for specific forwarding actions. This activity is significant as it may indicate unauthorized email redirection, potentially leading to data exfiltration. If confirmed malicious, attackers could intercept sensitive communications, leading to data breaches and information leakage.

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

*Source: [Splunk Security Content](detections/cloud/o365_new_email_forwarding_rule_enabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
