# O365 Multiple Users Failing To Authenticate From Ip

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where more than 10 unique user accounts fail to authenticate from a single IP address within a 5-minute window. This detection leverages O365 audit logs, specifically Azure Active Directory login failures (AzureActiveDirectoryStsLogon). Such activity is significant as it may indicate brute-force attacks or password spraying attempts. If confirmed malicious, this behavior suggests an external entity is attempting to breach security by targeting multiple accounts, potentially leading to unauthorized access. Immediate action is required to block or monitor the suspicious IP and notify affected users to enhance their security measures.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/o365_multiple_users_from_ip/o365_multiple_users_from_ip.log


---

*Source: [Splunk Security Content](detections/cloud/o365_multiple_users_failing_to_authenticate_from_ip.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
