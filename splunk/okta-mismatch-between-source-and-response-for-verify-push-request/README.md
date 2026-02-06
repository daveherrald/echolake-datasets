# Okta Mismatch Between Source and Response for Verify Push Request

**Type:** TTP

**Author:** John Murphy and Jordan Ruocco, Okta, Michael Haag, Bhavin Patel, Splunk

## Description

The following analytic identifies discrepancies between the source and response events for Okta Verify Push requests, indicating potential suspicious behavior. It leverages Okta System Log events, specifically `system.push.send_factor_verify_push` and `user.authentication.auth_via_mfa` with the factor "OKTA_VERIFY_PUSH." The detection groups events by SessionID, calculates the ratio of successful sign-ins to push requests, and checks for session roaming and new device/IP usage. This activity is significant as it may indicate push spam or unauthorized access attempts. If confirmed malicious, attackers could bypass MFA, leading to unauthorized access to sensitive systems.

## MITRE ATT&CK

- T1621

## Analytic Stories

- Okta Account Takeover
- Okta MFA Exhaustion
- Scattered Lapsus$ Hunters

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_mismatch/okta_mismatch.log


---

*Source: [Splunk Security Content](detections/application/okta_mismatch_between_source_and_response_for_verify_push_request.yml)*
