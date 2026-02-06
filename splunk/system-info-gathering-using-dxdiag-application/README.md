# System Info Gathering Using Dxdiag Application

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the execution of the dxdiag.exe process with specific command-line arguments, which is used to gather system information. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events and command-line details. This activity is significant because dxdiag.exe is rarely used in corporate environments and its execution may indicate reconnaissance efforts by malicious actors. If confirmed malicious, this activity could allow attackers to collect detailed system information, aiding in further exploitation or lateral movement within the network.

## MITRE ATT&CK

- T1592

## Analytic Stories

- Remcos

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1592/host_info_dxdiag/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/system_info_gathering_using_dxdiag_application.yml)*
