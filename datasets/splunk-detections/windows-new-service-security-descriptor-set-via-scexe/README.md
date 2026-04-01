# Windows New Service Security Descriptor Set Via Sc.EXE

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting changes in a service security descriptor where a new deny ace has been added. It leverages data from Endpoint Detection and Response (EDR) agents, specifically searching for any process execution involving the "sc.exe" binary with the "sdset" flag targeting any service and adding a dedicated deny ace. If confirmed malicious, this could allow an attacker to escalate their privileges, blind defenses and more.

## MITRE ATT&CK

- T1564

## Analytic Stories

- Defense Evasion or Unauthorized Access Via SDDL Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1564/sc_sdset_tampering/sc_sdset_tampering_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_new_service_security_descriptor_set_via_sc_exe.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
