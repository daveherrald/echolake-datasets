# Windows Terminating Lsass Process

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious process attempting to terminate the Lsass.exe process. It leverages Sysmon EventCode 10 logs to identify processes granted PROCESS_TERMINATE access to Lsass.exe. This activity is significant because Lsass.exe is a critical process responsible for enforcing security policies and handling user credentials. If confirmed malicious, this behavior could indicate an attempt to perform credential dumping, privilege escalation, or evasion of security policies, potentially leading to unauthorized access and persistence within the environment.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Data Destruction
- Double Zero Destructor
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/doublezero_wiper/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_terminating_lsass_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
