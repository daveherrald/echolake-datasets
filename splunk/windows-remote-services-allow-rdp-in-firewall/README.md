# Windows Remote Services Allow Rdp In Firewall

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows firewall to enable Remote Desktop Protocol (RDP) on a targeted machine. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving "netsh.exe" to allow TCP port 3389. This activity is significant as it may indicate an adversary attempting to gain remote access to a compromised host, a common tactic for lateral movement. If confirmed malicious, this could allow attackers to remotely control the system, leading to potential data exfiltration or further network compromise.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Azorult
- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/azorult/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_services_allow_rdp_in_firewall.yml)*
