# Windows Steal or Forge Kerberos Tickets Klist

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the execution of the Windows OS tool klist.exe, often used by post-exploitation tools like winpeas. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and parent process details. Monitoring klist.exe is significant as it can indicate attempts to list or gather cached Kerberos tickets, which are crucial for lateral movement or privilege escalation. If confirmed malicious, this activity could enable attackers to move laterally within the network or escalate privileges, posing a severe security risk.

## MITRE ATT&CK

- T1558

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_steal_or_forge_kerberos_tickets_klist.yml)*
