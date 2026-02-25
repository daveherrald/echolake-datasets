# O365 Disable MFA

**Type:** TTP

**Author:** Rod Soto, Splunk

## Description

This dataset contains sample data for identifying instances where Multi-Factor Authentication (MFA) is disabled for a user within the Office 365 environment. It leverages O365 audit logs, specifically focusing on events related to MFA settings. Disabling MFA removes a critical security layer, making accounts more vulnerable to unauthorized access. If confirmed malicious, this activity could indicate an attacker attempting to maintain persistence or an insider threat, significantly increasing the risk of unauthorized access. Immediate investigation is required to validate the reason for disabling MFA, potentially re-enable it, and assess any other suspicious activities related to the affected account.

## MITRE ATT&CK

- T1556

## Analytic Stories

- Office 365 Persistence Mechanisms

## Data Sources

- O365 Disable Strong Authentication.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/o365_disable_mfa/o365_disable_mfa.json


---

*Source: [Splunk Security Content](detections/cloud/o365_disable_mfa.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
