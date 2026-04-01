# Detect Excessive Account Lockouts From Endpoint

**Type:** Anomaly

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting endpoints causing a high number of account lockouts within a short period. It leverages the Windows security event logs ingested into the `Change` datamodel, specifically under the `Account_Management` node, to identify and count lockout events. This activity is significant as it may indicate a brute-force attack or misconfigured system causing repeated authentication failures. If confirmed malicious, this behavior could lead to account lockouts, disrupting user access and potentially indicating an ongoing attack attempting to compromise user credentials.

## MITRE ATT&CK

- T1078.002

## Analytic Stories

- Active Directory Password Spraying

## Data Sources


## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-security.log

- **Source:** WinEventLog:System
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-system.log

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.002/account_lockout/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_excessive_account_lockouts_from_endpoint.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
