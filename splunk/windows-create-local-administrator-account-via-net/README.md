# Windows Create Local Administrator Account Via Net

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects the creation of a local administrator account using the "net.exe" command. It leverages Endpoint Detection and Response (EDR) data to identify processes named "net.exe" with the "/add" parameter and keywords related to administrator accounts. This activity is significant as it may indicate an attacker attempting to gain persistent access or escalate privileges. If confirmed malicious, this could lead to unauthorized access, data theft, or further system compromise. Review the process details, user context, and related artifacts to determine the legitimacy of the activity.

## MITRE ATT&CK

- T1136.001

## Analytic Stories

- DHS Report TA18-074A
- CISA AA22-257A
- Medusa Ransomware
- CISA AA24-241A
- Azorult
- DarkGate Malware
- GhostRedirector IIS Module and Rungan Backdoor
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_create_local_administrator_account_via_net.yml)*
