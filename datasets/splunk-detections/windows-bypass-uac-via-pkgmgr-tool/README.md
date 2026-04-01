# Windows Bypass UAC via Pkgmgr Tool

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the deprecated 'pkgmgr.exe' process with an XML input file, which is unusual and potentially suspicious. This detection leverages Endpoint Detection and Response (EDR) telemetry, focusing on process execution details and command-line arguments. The significance lies in the deprecated status of 'pkgmgr.exe' and the use of XML files, which could indicate an attempt to bypass User Account Control (UAC). If confirmed malicious, this activity could allow an attacker to execute commands with elevated privileges, leading to potential system compromise and unauthorized changes.

## MITRE ATT&CK

- T1548.002

## Analytic Stories

- Warzone RAT

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/warzone_rat/pkgmgr_uac_bypass/pkgmgr_create_file.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_bypass_uac_via_pkgmgr_tool.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
