# O365 Multiple Failed MFA Requests For User

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies potential "MFA fatigue" attacks targeting Office 365 users by detecting more than nine Multi-Factor Authentication (MFA) prompts within a 10-minute timeframe. It leverages O365 management activity logs, focusing on Azure Active Directory events with the UserLoginFailed operation, a Success ResultStatus, and an ErrorNumber of 500121. This activity is significant as attackers may exploit MFA fatigue to gain unauthorized access by overwhelming users with repeated MFA requests. If confirmed malicious, this could lead to data breaches, unauthorized data access, or further compromise within the O365 environment. Immediate investigation is crucial.

## MITRE ATT&CK

- T1621

## Analytic Stories

- Office 365 Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- O365 UserLoginFailed

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/o365_multiple_failed_mfa_requests/o365_multiple_failed_mfa_requests.log


---

*Source: [Splunk Security Content](detections/cloud/o365_multiple_failed_mfa_requests_for_user.yml)*
