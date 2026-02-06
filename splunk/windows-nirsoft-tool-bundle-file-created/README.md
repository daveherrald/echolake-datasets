# Windows NirSoft Tool Bundle File Created

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the creation of files associated with the NirSoft
tool bundles on Windows endpoints.
NirSoft is a well-known provider of free, portable utilities that can be used for various system and network tasks. However, threat actors often leverage these tools for malicious purposes, such as credential harvesting, network reconnaissance, and data exfiltration.
The detection focuses on the creation of specific NirSoft tool bundle files, which may indicate that an attacker is preparing to use these utilities on a compromised system.
Security teams should investigate any instances of these files being created, especially if they are found in unexpected locations or on systems that should not be using such tools.


## MITRE ATT&CK

- T1588.002

## Analytic Stories

- Unusual Processes
- Data Destruction
- WhisperGate

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1588.002/nirsoft_tooling/nirsoft_file_bundle_created.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_nirsoft_tool_bundle_file_created.yml)*
