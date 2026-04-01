# O365 New MFA Method Registered

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the registration of a new Multi-Factor Authentication (MFA) method for a user account within Office 365. It leverages O365 audit logs to identify changes in MFA configurations. This activity is significant as it may indicate an attacker's attempt to maintain persistence on a compromised account. If confirmed malicious, the attacker could bypass existing security measures, solidify their access, and potentially escalate privileges or access sensitive data. Immediate verification and remediation are required to secure the affected account.

## MITRE ATT&CK

- T1098.005

## Analytic Stories

- Office 365 Persistence Mechanisms

## Data Sources

- O365 Update user.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.005/o365_register_new_mfa_method/o365_register_new_mfa_method.log


---

*Source: [Splunk Security Content](detections/cloud/o365_new_mfa_method_registered.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
