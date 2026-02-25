# Nishang PowershellTCPOneLine

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of the Nishang Invoke-PowerShellTCPOneLine utility, which initiates a callback to a remote Command and Control (C2) server. It leverages Endpoint Detection and Response (EDR) data, focusing on PowerShell processes that include specific .NET classes like Net.Sockets.TCPClient and System.Text.ASCIIEncoding. This activity is significant as it indicates potential remote control or data exfiltration attempts by an attacker. If confirmed malicious, this could lead to unauthorized remote access, data theft, or further compromise of the affected system.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- HAFNIUM Group
- Cleo File Transfer Software

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/nishang_powershelltcponeline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
