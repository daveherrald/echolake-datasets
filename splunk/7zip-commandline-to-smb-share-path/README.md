# 7zip CommandLine To SMB Share Path

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of 7z or 7za processes with command lines pointing to SMB network shares. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant as it may indicate an attempt to archive and exfiltrate sensitive files to a network share, a technique observed in CONTI LEAK tools. If confirmed malicious, this behavior could lead to data exfiltration, compromising sensitive information and potentially aiding further attacks.

## MITRE ATT&CK

- T1560.001

## Analytic Stories

- Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/conti_leak/windows-sysmon_7z.log


---

*Source: [Splunk Security Content](detections/endpoint/7zip_commandline_to_smb_share_path.yml)*
