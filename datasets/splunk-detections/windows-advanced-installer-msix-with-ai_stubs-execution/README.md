# Windows Advanced Installer MSIX with AI_STUBS Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the execution of Advanced Installer MSIX Package Support Framework (PSF) components, specifically the AI_STUBS executables with the original filename 'popupwrapper.exe'. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process paths and original filenames. This activity is significant as adversaries have been observed packaging malicious content within MSIX files built with Advanced Installer to bypass security controls. These AI_STUBS executables (with original filename 'popupwrapper.exe') are hallmark artifacts of potentially malicious MSIX packages. If confirmed malicious, this could allow attackers to execute arbitrary code, establish persistence, or deliver malware while evading traditional detection mechanisms.

## MITRE ATT&CK

- T1218
- T1553.005
- T1204.002

## Analytic Stories

- MSIX Package Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218/msix_ai_stubs/windows_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_advanced_installer_msix_with_ai_stubs_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
