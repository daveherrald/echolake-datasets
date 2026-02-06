# Windows Office Product Spawned Control

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances where `control.exe` is spawned by a Microsoft Office product. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process relationships. This activity is significant because it can indicate exploitation attempts related to CVE-2021-40444, where `control.exe` is used to execute malicious .cpl or .inf files. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- Microsoft MSHTML Remote Code Execution CVE-2021-40444
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_control.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_spawned_control.yml)*
