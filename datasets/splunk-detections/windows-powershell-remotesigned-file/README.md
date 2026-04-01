# Windows Powershell RemoteSigned File

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the use of the "remotesigned" execution policy for PowerShell scripts. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions containing "remotesigned" and "-File". This activity is significant because the "remotesigned" policy allows locally created scripts to run without restrictions, posing a potential security risk. If confirmed malicious, an attacker could execute unauthorized scripts, leading to code execution, privilege escalation, or persistence within the environment.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- Amadey

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_remotesigned/remotesigned_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_remotesigned_file.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
