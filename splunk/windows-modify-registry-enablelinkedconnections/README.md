# Windows Modify Registry EnableLinkedConnections

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious modification to the Windows registry setting for EnableLinkedConnections. It leverages data from the Endpoint.Registry datamodel to identify changes where the registry path is "*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLinkedConnections" and the value is set to "0x00000001". This activity is significant because enabling linked connections can allow network shares to be accessed with both standard and administrator-level privileges, a technique often abused by malware like BlackByte ransomware. If confirmed malicious, this could lead to unauthorized access to sensitive network resources, escalating the attacker's privileges.

## MITRE ATT&CK

- T1112

## Analytic Stories

- BlackByte Ransomware

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/blackbyte/enablelinkedconnections/blackbyte_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_enablelinkedconnections.yml)*
