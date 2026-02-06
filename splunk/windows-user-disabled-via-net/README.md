# Windows User Disabled Via Net

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the `net.exe` utility to disable a user account via the command line. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant as it may indicate an adversary's attempt to disrupt user availability, potentially as a precursor to further malicious actions. If confirmed malicious, this could lead to denial of service for legitimate users, aiding the attacker in maintaining control or covering their tracks.

## MITRE ATT&CK

- T1531

## Analytic Stories

- XMRig

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_user_disabled_via_net.yml)*
