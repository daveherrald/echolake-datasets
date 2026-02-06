# Windows Terminating Lsass Process

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious process attempting to terminate the Lsass.exe process. It leverages Sysmon EventCode 10 logs to identify processes granted PROCESS_TERMINATE access to Lsass.exe. This activity is significant because Lsass.exe is a critical process responsible for enforcing security policies and handling user credentials. If confirmed malicious, this behavior could indicate an attempt to perform credential dumping, privilege escalation, or evasion of security policies, potentially leading to unauthorized access and persistence within the environment.

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
