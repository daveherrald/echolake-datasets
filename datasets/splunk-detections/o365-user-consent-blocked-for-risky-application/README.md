# O365 User Consent Blocked for Risky Application

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where Office 365 has blocked a user's attempt to grant consent to an application deemed risky or potentially malicious. This detection leverages O365 audit logs, specifically focusing on failed user consent actions due to system-driven blocks. Monitoring these blocked consent attempts is crucial as it highlights potential threats early on, indicating that a user might be targeted or that malicious applications are attempting to infiltrate the organization. If confirmed malicious, this activity suggests that O365's security measures successfully prevented a harmful application from accessing organizational data, warranting immediate investigation.

## MITRE ATT&CK

- T1528

## Analytic Stories

- Office 365 Account Takeover

## Data Sources

- O365 Consent to application.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1528/o365_user_consent_blocked/o365_user_consent_blocked.log


---

*Source: [Splunk Security Content](detections/cloud/o365_user_consent_blocked_for_risky_application.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
