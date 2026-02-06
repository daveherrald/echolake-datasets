# Windows System User Discovery Via Quser

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the Windows OS tool quser.exe, commonly used to gather information about user sessions on a Remote Desktop Session Host server. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. Monitoring this activity is crucial as quser.exe is often abused by post-exploitation tools like winpeas, used in ransomware attacks to enumerate user sessions. If confirmed malicious, attackers could leverage this information to further compromise the system, maintain persistence, or escalate privileges.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Prestige Ransomware
- Crypto Stealer
- Windows Post-Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_user_discovery_via_quser.yml)*
