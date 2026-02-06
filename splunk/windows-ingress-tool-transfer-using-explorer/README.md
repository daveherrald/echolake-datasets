# Windows Ingress Tool Transfer Using Explorer

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies instances where the Windows Explorer process (explorer.exe) is executed with a URL in its command line. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs. This activity is significant because adversaries, such as those using DCRat malware, may abuse explorer.exe to open URLs with the default browser, which is an uncommon and suspicious behavior. If confirmed malicious, this technique could allow attackers to download and execute malicious payloads, leading to potential system compromise and further malicious activities.

## MITRE ATT&CK

- T1105

## Analytic Stories

- DarkCrystal RAT

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/dcrat/dcrat_explorer_url/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ingress_tool_transfer_using_explorer.yml)*
