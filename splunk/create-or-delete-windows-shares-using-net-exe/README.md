# Create or delete windows shares using net exe

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects the creation or deletion of Windows shares using the net.exe command. It leverages Endpoint Detection and Response (EDR) data to identify processes involving net.exe with actions related to share management. This activity is significant because it may indicate an attacker attempting to manipulate network shares for malicious purposes, such as data exfiltration, malware distribution, or establishing persistence. If confirmed malicious, this activity could lead to unauthorized access to sensitive information, service disruption, or malware introduction. Immediate investigation is required to determine the intent and mitigate potential threats.

## MITRE ATT&CK

- T1070.005

## Analytic Stories

- Hidden Cobra Malware
- CISA AA22-277A
- Windows Post-Exploitation
- Prestige Ransomware
- DarkGate Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.005/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/create_or_delete_windows_shares_using_net_exe.yml)*
