# GCP Multiple Failed MFA Requests For User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects multiple failed multi-factor authentication (MFA) requests for a single user within a Google Cloud Platform (GCP) tenant. It triggers when 10 or more MFA prompts fail within a 5-minute window, using Google Workspace login failure events. This behavior is significant as it may indicate an adversary attempting to bypass MFA by bombarding the user with repeated authentication requests. If confirmed malicious, this activity could lead to unauthorized access, allowing attackers to compromise accounts and potentially escalate privileges within the GCP environment.

## MITRE ATT&CK

- T1078.004
- T1586.003
- T1621

## Analytic Stories

- GCP Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Google Workspace

## Sample Data

- **Source:** gws:reports:login
  **Sourcetype:** gws:reports:login
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/multiple_failed_mfa_gws/gws_login.log


---

*Source: [Splunk Security Content](detections/cloud/gcp_multiple_failed_mfa_requests_for_user.yml)*
