# Okta Authentication Failed During MFA Challenge

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying failed authentication attempts during the Multi-Factor Authentication (MFA) challenge in an Okta tenant. It uses the Authentication datamodel to detect specific failed events where the authentication signature is `user.authentication.auth_via_mfa`. This activity is significant as it may indicate an adversary attempting to authenticate with compromised credentials on an account with MFA enabled. If confirmed malicious, this could suggest an ongoing attempt to bypass MFA protections, potentially leading to unauthorized access and further compromise of the affected account.

## MITRE ATT&CK

- T1078.004
- T1586.003
- T1621

## Analytic Stories

- Okta Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Okta

## Sample Data

- **Source:** okta_log
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_mfa_login_failed/okta_mfa_login_failed.log


---

*Source: [Splunk Security Content](detections/application/okta_authentication_failed_during_mfa_challenge.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
