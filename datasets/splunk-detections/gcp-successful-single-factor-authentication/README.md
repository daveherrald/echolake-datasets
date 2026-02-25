# GCP Successful Single-Factor Authentication

**Type:** TTP

**Author:** Bhavin Patel, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying a successful single-factor authentication event against Google Cloud Platform (GCP) for an account without Multi-Factor Authentication (MFA) enabled. It uses Google Workspace login event data to detect instances where MFA is not utilized. This activity is significant as it may indicate a misconfiguration, policy violation, or potential account takeover attempt. If confirmed malicious, an attacker could gain unauthorized access to GCP resources, potentially leading to data breaches, service disruptions, or further exploitation within the cloud environment.

## MITRE ATT&CK

- T1078.004
- T1586.003

## Analytic Stories

- GCP Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Google Workspace

## Sample Data

- **Source:** gws:reports:login
  **Sourcetype:** gws:reports:login
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/gcp_single_factor_auth/gws_login.log


---

*Source: [Splunk Security Content](detections/cloud/gcp_successful_single_factor_authentication.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
