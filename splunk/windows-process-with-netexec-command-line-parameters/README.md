# Windows Process With NetExec Command Line Parameters

**Type:** TTP

**Author:** Steven Dick, Github Community

## Description

The following analytic detects the use of NetExec (formally CrackmapExec) a toolset used for post-exploitation enumeration and attack within Active Directory environments through command line parameters. It leverages Endpoint Detection and Response (EDR) data to identify specific command-line arguments associated with actions like ticket manipulation, kerberoasting, and password spraying. This activity is significant as NetExec is used by adversaries to exploit Kerberos for privilege escalation and lateral movement. If confirmed malicious, this could lead to unauthorized access, persistence, and potential compromise of sensitive information within the network.

## MITRE ATT&CK

- T1550.003
- T1558.003
- T1558.004

## Analytic Stories

- Active Directory Kerberos Attacks
- Active Directory Privilege Escalation

## Data Sources

- Windows Event Log Security 4688
- Sysmon EventID 1
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/netexec_toolkit_usage/netexec_toolkit_usage.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_with_netexec_command_line_parameters.yml)*
