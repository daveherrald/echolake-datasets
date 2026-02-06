# Windows Remote Access Software RMS Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation or modification of Windows registry entries related to the Remote Manipulator System (RMS) Remote Admin tool. It leverages data from the Endpoint.Registry datamodel, focusing on registry paths containing "SYSTEM\\Remote Manipulator System." This activity is significant because RMS, while legitimate, is often abused by adversaries, such as in the Azorult malware campaigns, to gain unauthorized remote access. If confirmed malicious, this could allow attackers to remotely control the targeted host, leading to potential data exfiltration, system manipulation, or further network compromise.

## MITRE ATT&CK

- T1219

## Analytic Stories

- Azorult

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_access_software_rms_registry.yml)*
