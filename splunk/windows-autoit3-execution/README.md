# Windows AutoIt3 Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of AutoIt3, a scripting
language often used for automating Windows GUI tasks and general scripting. 
It identifies instances where AutoIt3 or its variants are executed by searching for process names
or original file names matching 'autoit3.exe'. 
This activity is significant because attackers frequently use AutoIt3 to automate malicious actions, such as executing malware. 
If confirmed malicious, this activity could lead to unauthorized code execution, 
system compromise, or further propagation of malware within the environment.


## MITRE ATT&CK

- T1059

## Analytic Stories

- Crypto Stealer
- Handala Wiper
- DarkGate Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/autoit/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_autoit3_execution.yml)*
