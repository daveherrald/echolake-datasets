# O365 Mailbox Email Forwarding Enabled

**Type:** TTP

**Author:** Patrick Bareiss, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where email forwarding has been enabled on mailboxes within an Office 365 environment. It detects this activity by monitoring the Set-Mailbox operation within the o365_management_activity logs, specifically looking for changes to the ForwardingAddress or ForwardingSmtpAddress parameters. This activity is significant as unauthorized email forwarding can lead to data exfiltration and unauthorized access to sensitive information. If confirmed malicious, attackers could intercept and redirect emails, potentially compromising confidential communications and leading to data breaches.

## MITRE ATT&CK

- T1114.003

## Analytic Stories

- Office 365 Collection Techniques

## Data Sources


## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1114.003/o365_mailbox_forwarding_enabled/o365_mailbox_forwarding_enabled.json


---

*Source: [Splunk Security Content](detections/cloud/o365_mailbox_email_forwarding_enabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
