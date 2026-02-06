# Rubeus Command Line Parameters

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the use of Rubeus command line parameters, a toolset for Kerberos attacks within Active Directory environments. It leverages Endpoint Detection and Response (EDR) data to identify specific command-line arguments associated with actions like ticket manipulation, kerberoasting, and password spraying. This activity is significant as Rubeus is commonly used by adversaries to exploit Kerberos for privilege escalation and lateral movement. If confirmed malicious, this could lead to unauthorized access, persistence, and potential compromise of sensitive information within the network.

## MITRE ATT&CK

- T1550.003
- T1558.003
- T1558.004

## Analytic Stories

- Active Directory Privilege Escalation
- CISA AA23-347A
- Active Directory Kerberos Attacks
- BlackSuit Ransomware
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.003/rubeus/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rubeus_command_line_parameters.yml)*
