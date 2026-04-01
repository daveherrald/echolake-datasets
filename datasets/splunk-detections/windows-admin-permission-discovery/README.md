# Windows Admin Permission Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the creation of a suspicious file named 'win.dat' in the root directory (C:\). It leverages data from the Endpoint.Filesystem datamodel to detect this activity. This behavior is significant as it is commonly used by malware like NjRAT to check for administrative privileges on a compromised host. If confirmed malicious, this activity could indicate that the malware has administrative access, allowing it to perform high-privilege actions, potentially leading to further system compromise and persistence.

## MITRE ATT&CK

- T1069.001

## Analytic Stories

- NjRAT

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1069.001/njrat_admin_check/win_dat.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_admin_permission_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
