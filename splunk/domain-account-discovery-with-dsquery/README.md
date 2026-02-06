# Domain Account Discovery with Dsquery

**Type:** Anomaly

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

The following analytic identifies the execution of `dsquery.exe` with command-line arguments used to discover domain users. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it indicates potential reconnaissance efforts by adversaries to map out domain users, which is a common precursor to further attacks. If confirmed malicious, this behavior could allow attackers to gain insights into user accounts, facilitating subsequent actions like privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery
- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.002/AD_discovery/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/domain_account_discovery_with_dsquery.yml)*
