# Active Setup Registry Autostart

**Type:** TTP

**Author:** Steven Dick, Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious modifications to the Active Setup registry for persistence and privilege escalation. It leverages data from the Endpoint.Registry data model, focusing on changes to the "StubPath" value within the "SOFTWARE\\Microsoft\\Active Setup\\Installed Components" path. This activity is significant as it is commonly used by malware, adware, and APTs to maintain persistence on compromised machines. If confirmed malicious, this could allow attackers to execute code upon system startup, potentially leading to further system compromise and unauthorized access.

## MITRE ATT&CK

- T1547.014

## Analytic Stories

- Data Destruction
- Windows Privilege Escalation
- Hermetic Wiper
- Windows Persistence Techniques

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1547.014/active_setup_stubpath/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/active_setup_registry_autostart.yml)*
