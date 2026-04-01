# Windows ScManager Security Descriptor Tampering Via Sc.EXE

**Type:** TTP

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting changes in the ScManager service security descriptor settings. It leverages data from Endpoint Detection and Response (EDR) agents, specifically searching for any process execution involving the "sc.exe" binary with the "sdset" flag targeting the "scmanager" service. If confirmed malicious, this could allow an attacker to escalate their privileges.

## MITRE ATT&CK

- T1569.002

## Analytic Stories

- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/scmanager_sddl_tamper/scmanager_sddl_tamper_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_scmanager_security_descriptor_tampering_via_sc_exe.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
