# Okta Multi-Factor Authentication Disabled

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying an attempt to disable multi-factor authentication (MFA) for an Okta user. It leverages OktaIM2 logs to detect when the 'user.mfa.factor.deactivate' command is executed. This activity is significant because disabling MFA can allow an adversary to maintain persistence within the environment using a compromised valid account. If confirmed malicious, this action could enable attackers to bypass additional security layers, potentially leading to unauthorized access to sensitive information and prolonged undetected presence in the network.

## MITRE ATT&CK

- T1556.006

## Analytic Stories

- Okta Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.006/okta_mfa_method_disabled/okta_mfa_method_disabled.log


---

*Source: [Splunk Security Content](detections/application/okta_multi_factor_authentication_disabled.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
