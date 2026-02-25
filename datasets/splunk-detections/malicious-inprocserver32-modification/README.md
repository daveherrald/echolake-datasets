# Malicious InProcServer32 Modification

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting a process modifying the registry with a known malicious CLSID under InProcServer32. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on registry modifications within the HKLM or HKCU Software Classes CLSID paths. This activity is significant as it may indicate an attempt to load a malicious DLL, potentially leading to code execution. If confirmed malicious, this could allow an attacker to persist in the environment, execute arbitrary code, or escalate privileges, posing a severe threat to system integrity and security.

## MITRE ATT&CK

- T1218.010
- T1112

## Analytic Stories

- Suspicious Regsvr32 Activity
- Remcos

## Data Sources

- Sysmon EventID 12
- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/remcos/remcos/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/malicious_inprocserver32_modification.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
