# Windows Process Execution From RDP Share

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic identifies process executions originating from RDP shares on Windows endpoints.
Remote Desktop Protocol (RDP) shares, typically accessed via the "tsclient" path, allow users to share files between their local machine and a remote desktop session. However, threat actors may exploit RDP shares to execute malicious processes or transfer harmful files onto a compromised system.
This detection focuses on identifying any process executions that originate from RDP shares, which could indicate unauthorized access or malicious activity.
Security teams should investigate any instances of such process executions, especially if they are found on systems that should not be using RDP shares or if the executed processes are unfamiliar or suspicious.


## MITRE ATT&CK

- T1021.001
- T1105
- T1059

## Analytic Stories

- Hidden Cobra Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.001/execution_from_rdp_share/execution_from_rdp_share.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_execution_from_rdp_share.yml)*
