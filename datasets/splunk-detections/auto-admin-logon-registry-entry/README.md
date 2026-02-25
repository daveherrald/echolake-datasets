# Auto Admin Logon Registry Entry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

This dataset contains sample data for detecting a suspicious registry modification that enables auto admin logon on a host. It leverages data from the Endpoint.Registry data model, specifically looking for changes to the "AutoAdminLogon" value within the "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" registry path. This activity is significant because it was observed in BlackMatter ransomware attacks to maintain access after a safe mode reboot, facilitating further encryption. If confirmed malicious, this could allow attackers to automatically log in and continue their operations, potentially leading to widespread network encryption and data loss.

## MITRE ATT&CK

- T1552.002

## Analytic Stories

- BlackMatter Ransomware
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.002/autoadminlogon/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/auto_admin_logon_registry_entry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
