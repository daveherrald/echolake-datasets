# Shim Database File Creation

**Type:** TTP

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting the creation of shim database files (.sdb) in default directories using the sdbinst.exe application. It leverages filesystem activity data from the Endpoint.Filesystem data model to identify file writes to the Windows\AppPatch\Custom directory. This activity is significant because shims can intercept and alter API calls, potentially allowing attackers to bypass security controls or execute malicious code. If confirmed malicious, this could lead to unauthorized code execution, privilege escalation, or persistent access within the environment.

## MITRE ATT&CK

- T1546.011

## Analytic Stories

- Windows Persistence Techniques

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.011/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/shim_database_file_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
