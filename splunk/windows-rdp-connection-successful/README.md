# Windows RDP Connection Successful

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects successful Remote Desktop Protocol (RDP) connections by monitoring EventCode 1149 from the Windows TerminalServices RemoteConnectionManager Operational log. This detection is significant as successful RDP connections can indicate remote access to a system, which may be leveraged by attackers to control or exfiltrate data. If confirmed malicious, this activity could lead to unauthorized access, data theft, or further lateral movement within the network. Monitoring successful RDP connections is crucial for identifying potential security breaches and mitigating risks promptly.

## MITRE ATT&CK

- T1563.002

## Analytic Stories

- Active Directory Lateral Movement
- BlackByte Ransomware
- Windows RDP Artifacts and Defense Evasion
- Interlock Ransomware
- NetSupport RMM Tool Abuse

## Data Sources

- Windows Event Log RemoteConnectionManager 1149

## Sample Data

- **Source:** WinEventLog:Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1563.002/windows_rdp_connection_successful/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_connection_successful.yml)*
