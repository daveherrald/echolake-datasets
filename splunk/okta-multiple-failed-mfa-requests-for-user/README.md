# Okta Multiple Failed MFA Requests For User

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies multiple failed multi-factor authentication (MFA) requests for a single user within an Okta tenant. It triggers when more than 10 MFA attempts fail within 5 minutes, using Okta event logs to detect this pattern. This activity is significant as it may indicate an adversary attempting to bypass MFA by bombarding the user with repeated authentication requests, a technique used by threat actors like Lapsus and APT29. If confirmed malicious, this could lead to unauthorized access, potentially compromising sensitive information and systems.

## MITRE ATT&CK

- T1621

## Analytic Stories

- Okta Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_multiple_failed_mfa_requests/okta_multiple_failed_mfa_requests.log


---

*Source: [Splunk Security Content](detections/application/okta_multiple_failed_mfa_requests_for_user.yml)*
