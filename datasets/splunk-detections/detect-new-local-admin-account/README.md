# Detect New Local Admin account

**Type:** TTP

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting the creation of new accounts elevated to local administrators. It uses Windows event logs, specifically EventCode 4720 (user account creation) and EventCode 4732 (user added to Administrators group). This activity is significant as it indicates potential unauthorized privilege escalation, which is critical for SOC monitoring. If confirmed malicious, this could allow attackers to gain administrative access, leading to unauthorized data access, system modifications, and disruption of services. Immediate investigation is required to mitigate risks and prevent further unauthorized actions.

## MITRE ATT&CK

- T1136.001

## Analytic Stories

- DHS Report TA18-074A
- HAFNIUM Group
- CISA AA22-257A
- CISA AA24-241A
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4732
- Windows Event Log Security 4720

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-security.log

- **Source:** WinEventLog:System
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-system.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_new_local_admin_account.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
