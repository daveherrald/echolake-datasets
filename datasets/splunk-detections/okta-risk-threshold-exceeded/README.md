# Okta Risk Threshold Exceeded

**Type:** Correlation

**Author:** Michael Haag, Bhavin Patel, Splunk

## Description

The following correlation identifies when a user exceeds a risk threshold based on multiple suspicious Okta activities. It leverages the Risk Framework from Enterprise Security, aggregating risk events from "Suspicious Okta Activity," "Okta Account Takeover," and "Okta MFA Exhaustion" analytic stories. This detection is significant as it highlights potentially compromised user accounts exhibiting multiple tactics, techniques, and procedures (TTPs) within a 24-hour period. If confirmed malicious, this activity could indicate a serious security breach, allowing attackers to gain unauthorized access, escalate privileges, or persist within the environment.

## MITRE ATT&CK

- T1078
- T1110

## Analytic Stories

- Okta Account Takeover
- Okta MFA Exhaustion
- Suspicious Okta Activity

## Data Sources

- Okta

## Sample Data

- **Source:** risk_data
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/okta_account_takeover_risk_events/okta_risk.log


---

*Source: [Splunk Security Content](detections/application/okta_risk_threshold_exceeded.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
