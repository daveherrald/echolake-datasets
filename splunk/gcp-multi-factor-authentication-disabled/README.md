# GCP Multi-Factor Authentication Disabled

**Type:** TTP

**Author:** Bhavin Patel, Mauricio Velazco, Splunk

## Description

The following analytic detects an attempt to disable multi-factor authentication (MFA) for a Google Cloud Platform (GCP) user. It leverages Google Workspace Admin log events, specifically the `UNENROLL_USER_FROM_STRONG_AUTH` command. This activity is significant because disabling MFA can allow an adversary to maintain persistence within the environment using a compromised account without raising suspicion. If confirmed malicious, this action could enable attackers to bypass additional security layers, potentially leading to unauthorized access, data exfiltration, or further exploitation of the compromised account.

## MITRE ATT&CK

- T1556.006
- T1586.003

## Analytic Stories

- GCP Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Google Workspace

## Sample Data

- **Source:** gws:reports:admin
  **Sourcetype:** gws:reports:admin
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/gcp_disable_mfa/gws_admin.log


---

*Source: [Splunk Security Content](detections/cloud/gcp_multi_factor_authentication_disabled.yml)*
