# Suspicious Rundll32 PluginInit

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the execution of the rundll32.exe process with the "plugininit" parameter. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events and command-line arguments. This activity is significant because the "plugininit" parameter is commonly associated with IcedID malware, which uses it to execute an initial DLL stager to download additional payloads. If confirmed malicious, this behavior could lead to further malware infections, data exfiltration, or complete system compromise.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- IcedID

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_rundll32_plugininit.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
