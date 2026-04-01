# GCP Authentication Failed During MFA Challenge

**Type:** TTP

**Author:** Bhavin Patel, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting failed authentication attempts during the Multi-Factor Authentication (MFA) challenge on a Google Cloud Platform (GCP) tenant. It uses Google Workspace login failure events to identify instances where MFA methods were challenged but not successfully completed. This activity is significant as it may indicate an adversary attempting to access an account with compromised credentials despite MFA protection. If confirmed malicious, this could lead to unauthorized access attempts, potentially compromising sensitive data and resources within the GCP environment.

## MITRE ATT&CK

- T1078.004
- T1586.003
- T1621

## Analytic Stories

- GCP Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Google Workspace login_failure

## Sample Data

- **Source:** gws:reports:login
  **Sourcetype:** gws:reports:login
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/gcp_failed_mfa/gws_login.log


---

*Source: [Splunk Security Content](detections/cloud/gcp_authentication_failed_during_mfa_challenge.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
