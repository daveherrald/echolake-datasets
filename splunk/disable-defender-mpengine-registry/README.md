# Disable Defender MpEngine Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk, Steven Dick

## Description

The following analytic detects the modification of the Windows Defender MpEngine registry value, specifically setting MpEnablePus to 0x00000000. This detection leverages endpoint registry logs, focusing on changes within the path "*\\Policies\\Microsoft\\Windows Defender\\MpEngine*". This activity is significant as it indicates an attempt to disable key Windows Defender features, potentially allowing malware to evade detection. If confirmed malicious, this could lead to undetected malware execution, persistence, and further system compromise. Immediate investigation and endpoint isolation are recommended.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- IcedID
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/disable_av/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/disable_defender_mpengine_registry.yml)*
