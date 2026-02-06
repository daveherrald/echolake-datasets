# Batch File Write to System32

**Type:** TTP

**Author:** Steven Dick, Michael Haag, Rico Valdez, Splunk

## Description

The following analytic detects the creation of a batch file (.bat) within the Windows system directory tree, specifically in the System32 or SysWOW64 folders. It leverages data from the Endpoint datamodel, focusing on process and filesystem events to identify this behavior. This activity is significant because writing batch files to system directories can be indicative of malicious intent, such as persistence mechanisms or system manipulation. If confirmed malicious, this could allow an attacker to execute arbitrary commands with elevated privileges, potentially compromising the entire system.

## MITRE ATT&CK

- T1204.002

## Analytic Stories

- SamSam Ransomware
- Compromised Windows Host

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.002/batch_file_in_system32/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/batch_file_write_to_system32.yml)*
