# GitHub Organizations Disable 2FA Requirement

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting when two-factor authentication (2FA) requirements are disabled in GitHub Organizations. The detection monitors GitHub Organizations audit logs for 2FA requirement changes by tracking actor details, organization information, and associated metadata. For a SOC, identifying disabled 2FA requirements is critical as it could indicate attempts to weaken account security controls. Two-factor authentication is a fundamental security control that helps prevent unauthorized access even if passwords are compromised. Disabling 2FA requirements could allow attackers to more easily compromise accounts through password-based attacks. The impact of disabled 2FA includes increased risk of account takeover, potential access to sensitive code and intellectual property, and compromise of the software supply chain. This activity could be part of a larger attack chain where an adversary first disables security controls before attempting broader account compromises.

## MITRE ATT&CK

- T1562.001
- T1195

## Analytic Stories

- GitHub Malicious Activity

## Data Sources

- GitHub Organizations Audit Logs

## Sample Data

- **Source:** github
  **Sourcetype:** github:cloud:audit
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/github_disable_two_factor_requirement/github.json


---

*Source: [Splunk Security Content](detections/cloud/github_organizations_disable_2fa_requirement.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
