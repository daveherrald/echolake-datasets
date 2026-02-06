# Resize ShadowStorage volume

**Type:** TTP

**Author:** Teoderick Contreras

## Description

The following analytic identifies the resizing of shadow storage volumes, a technique used by ransomware like CLOP to prevent the recreation of shadow volumes. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving "vssadmin.exe" with parameters related to resizing shadow storage. This activity is significant as it indicates an attempt to hinder recovery efforts by manipulating shadow copies. If confirmed malicious, this could lead to successful ransomware deployment, making data recovery difficult and increasing the potential for data loss.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Medusa Ransomware
- Clop Ransomware
- Compromised Windows Host
- BlackByte Ransomware
- VanHelsing Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/resize_shadowstorage_volume.yml)*
