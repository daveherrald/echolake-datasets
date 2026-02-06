# Windows PowerShell Get CIMInstance Remote Computer

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of the Get-CimInstance cmdlet with the -ComputerName parameter, indicating an attempt to retrieve information from a remote computer. It leverages PowerShell Script Block Logging to identify this specific command execution. This activity is significant as it may indicate unauthorized remote access or information gathering by an attacker. If confirmed malicious, this could allow the attacker to collect sensitive data from remote systems, potentially leading to further exploitation or lateral movement within the network.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Active Directory Lateral Movement

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/get_ciminstance_windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_get_ciminstance_remote_computer.yml)*
