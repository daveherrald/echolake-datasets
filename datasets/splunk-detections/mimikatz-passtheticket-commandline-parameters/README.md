# Mimikatz PassTheTicket CommandLine Parameters

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the use of Mimikatz command line parameters associated with pass-the-ticket attacks. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command-line patterns related to Kerberos ticket manipulation. This activity is significant because pass-the-ticket attacks allow adversaries to move laterally within an environment using stolen Kerberos tickets, bypassing normal access controls. If confirmed malicious, this could enable attackers to escalate privileges, access sensitive information, and maintain persistence within the network.

## MITRE ATT&CK

- T1550.003

## Analytic Stories

- Sandworm Tools
- CISA AA23-347A
- CISA AA22-320A
- Active Directory Kerberos Attacks
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550.003/mimikatz/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/mimikatz_passtheticket_commandline_parameters.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
