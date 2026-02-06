# Unknown Process Using The Kerberos Protocol

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies a non-lsass.exe process making an outbound connection on port 88, which is typically used by the Kerberos authentication protocol. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and network traffic logs. This activity is significant because, under normal circumstances, only the lsass.exe process should interact with the Kerberos Distribution Center. If confirmed malicious, this behavior could indicate an adversary attempting to abuse the Kerberos protocol, potentially leading to unauthorized access or lateral movement within the network.

## MITRE ATT&CK

- T1550

## Analytic Stories

- Active Directory Kerberos Attacks
- BlackSuit Ransomware

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3

## Sample Data

- **Source:** WinEventLog:Security
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/rubeus/windows-security.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1550/rubeus/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/unknown_process_using_the_kerberos_protocol.yml)*
