# Detect Remote Access Software Usage Process

**Type:** Anomaly

**Author:** Steven Dick, Sebastian Wurl, Splunk Community

## Description

The following analytic detects the execution of known remote access software within the environment. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and parent processes mapped to the Endpoint data model. We then compare with with a list of known remote access software shipped as a lookup file - remote_access_software. This activity is significant as adversaries often use remote access tools like AnyDesk, GoToMyPC, LogMeIn, and TeamViewer to maintain unauthorized access. If confirmed malicious, this could allow attackers to control systems remotely, exfiltrate data, or deploy additional malware, posing a severe threat to the organization's security.

## MITRE ATT&CK

- T1219

## Analytic Stories

- Insider Threat
- Command And Control
- Ransomware
- Gozi Malware
- CISA AA24-241A
- Remote Monitoring and Management Software
- Cactus Ransomware
- Seashell Blizzard
- Scattered Spider
- Interlock Ransomware
- GhostRedirector IIS Module and Rungan Backdoor
- Scattered Lapsus$ Hunters
- Storm-0501 Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1219/screenconnect/screenconnect_sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1219/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_remote_access_software_usage_process.yml)*
