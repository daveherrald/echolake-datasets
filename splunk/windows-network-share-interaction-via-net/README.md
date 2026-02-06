# Windows Network Share Interaction Via Net

**Type:** Anomaly

**Author:** Dean Luxton

## Description

The following analytic identifies network share discovery and collection activities performed on Windows systems using the Net command. Attackers often use network share discovery to identify accessible shared resources within a network, which can be a precursor to privilege escalation or data exfiltration. By monitoring Windows Event Logs for the usage of the Net command to list and interact with network shares, this detection helps identify potential reconnaissance and collection activities.

## MITRE ATT&CK

- T1135
- T1039

## Analytic Stories

- Active Directory Discovery
- Active Directory Privilege Escalation
- Network Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1135/net_share/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_network_share_interaction_via_net.yml)*
