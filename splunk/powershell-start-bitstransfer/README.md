# PowerShell Start-BitsTransfer

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of the PowerShell command `Start-BitsTransfer`, which can be used for file transfers, including potential data exfiltration. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events and command-line arguments. This activity is significant because `Start-BitsTransfer` can be abused by adversaries to upload sensitive files to remote locations, posing a risk of data loss. If confirmed malicious, this could lead to unauthorized data exfiltration, compromising sensitive information and potentially leading to further exploitation of the network.

## MITRE ATT&CK

- T1197

## Analytic Stories

- BITS Jobs
- Gozi Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1197/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_start_bitstransfer.yml)*
