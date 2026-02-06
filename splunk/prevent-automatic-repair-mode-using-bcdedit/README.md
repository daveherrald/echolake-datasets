# Prevent Automatic Repair Mode using Bcdedit

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of "bcdedit.exe" with parameters to set the boot status policy to ignore all failures. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. This activity is significant because it can indicate an attempt by ransomware to prevent a compromised machine from booting into automatic repair mode, thereby hindering recovery efforts. If confirmed malicious, this action could allow attackers to maintain control over the infected system, complicating remediation and potentially leading to further damage.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Ransomware
- Chaos Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ransomware_ttp/data1/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/prevent_automatic_repair_mode_using_bcdedit.yml)*
