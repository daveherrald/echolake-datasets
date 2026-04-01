# PingID New MFA Method Registered For User

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting the registration of a new Multi-Factor Authentication (MFA) method for a PingID (PingOne) account. It leverages JSON logs from PingID, specifically looking for successful device pairing events. This activity is significant as adversaries who gain unauthorized access to a user account may register a new MFA method to maintain persistence. If confirmed malicious, this could allow attackers to bypass existing security measures, maintain long-term access, and potentially escalate their privileges within the compromised environment.

## MITRE ATT&CK

- T1621
- T1556.006
- T1098.005

## Analytic Stories

- Compromised User Account

## Data Sources

- PingID

## Sample Data

- **Source:** PINGID
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1621/pingid/pingid.log


---

*Source: [Splunk Security Content](detections/application/pingid_new_mfa_method_registered_for_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
