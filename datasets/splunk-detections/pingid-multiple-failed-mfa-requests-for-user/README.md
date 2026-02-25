# PingID Multiple Failed MFA Requests For User

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying multiple failed multi-factor authentication (MFA) requests for a single user within a PingID environment. It triggers when 10 or more MFA prompts fail within 10 minutes, using JSON logs from PingID. This activity is significant as it may indicate an adversary attempting to bypass MFA by bombarding the user with repeated authentication requests. If confirmed malicious, this could lead to unauthorized access, as the user might eventually accept the fraudulent request, compromising the security of the account and potentially the entire network.

## MITRE ATT&CK

- T1621
- T1078
- T1110

## Analytic Stories

- Compromised User Account

## Data Sources

- PingID

## Sample Data

- **Source:** PINGID
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/pingid/pingid.log


---

*Source: [Splunk Security Content](detections/application/pingid_multiple_failed_mfa_requests_for_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
