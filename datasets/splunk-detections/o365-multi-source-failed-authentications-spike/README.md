# O365 Multi-Source Failed Authentications Spike

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a spike in failed authentication attempts within an Office 365 environment, indicative of a potential distributed password spraying attack. It leverages UserLoginFailed events from O365 Management Activity logs, focusing on ErrorNumber 50126. This detection is significant as it highlights attempts to bypass security controls using multiple IP addresses and user agents. If confirmed malicious, this activity could lead to unauthorized access, data breaches, privilege escalation, and lateral movement within the organization. Early detection is crucial to prevent account takeovers and mitigate subsequent threats.

## MITRE ATT&CK

- T1110.003
- T1110.004
- T1586.003

## Analytic Stories

- Office 365 Account Takeover
- NOBELIUM Group

## Data Sources

- O365 UserLoginFailed

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/o365_distributed_spray/o365_distributed_spray.log


---

*Source: [Splunk Security Content](detections/cloud/o365_multi_source_failed_authentications_spike.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
