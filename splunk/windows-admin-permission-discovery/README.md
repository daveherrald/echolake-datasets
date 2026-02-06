# Windows Admin Permission Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the creation of a suspicious file named 'win.dat' in the root directory (C:\). It leverages data from the Endpoint.Filesystem datamodel to detect this activity. This behavior is significant as it is commonly used by malware like NjRAT to check for administrative privileges on a compromised host. If confirmed malicious, this activity could indicate that the malware has administrative access, allowing it to perform high-privilege actions, potentially leading to further system compromise and persistence.

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
