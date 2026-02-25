# O365 High Number Of Failed Authentications for User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying an O365 account experiencing more than 20 failed authentication attempts within 5 minutes. It uses O365 Unified Audit Logs, specifically "UserLoginFailed" events, to monitor and flag accounts exceeding this threshold. This activity is significant as it may indicate a brute force attack or password guessing attempt. If confirmed malicious, an attacker could gain unauthorized access to the O365 environment, potentially compromising sensitive emails, documents, and other data. Prompt investigation and action are crucial to prevent unauthorized access and data breaches.

## MITRE ATT&CK

- T1110.001

## Analytic Stories

- Office 365 Account Takeover

## Data Sources

- O365 UserLoginFailed

## Sample Data

- **Source:** o365:management:activity
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/o365_high_number_authentications_for_user/o365_high_number_authentications_for_user.log


---

*Source: [Splunk Security Content](detections/cloud/o365_high_number_of_failed_authentications_for_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
