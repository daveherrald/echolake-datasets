# Okta MFA Exhaustion Hunt

**Type:** Hunting

**Author:** Michael Haag, Marissa Bower, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting patterns of successful and failed Okta MFA push attempts to identify potential MFA exhaustion attacks. It leverages Okta event logs, specifically focusing on push verification events, and uses statistical evaluations to determine suspicious activity. This activity is significant as it may indicate an attacker attempting to bypass MFA by overwhelming the user with push notifications. If confirmed malicious, this could lead to unauthorized access, compromising the security of the affected accounts and potentially the entire environment.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Okta Account Takeover
- Okta MFA Exhaustion
- Scattered Lapsus$ Hunters

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/okta_multiple_failed_mfa_pushes/okta_multiple_failed_mfa_pushes.log


---

*Source: [Splunk Security Content](detections/application/okta_mfa_exhaustion_hunt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
