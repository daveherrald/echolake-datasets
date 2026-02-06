# Windows RMM Named Pipe

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

The following analytic detects the creation or connection to known suspicious named pipes, which is a technique often used by offensive tools.
It leverages Sysmon EventCodes 17 and 18 to identify  known default pipe names used by RMM tools.
If confirmed malicious,  this could allow an attacker to abuse these to potentially gain persistence, command and control, or further system compromise.


## MITRE ATT&CK

- T1559
- T1021.002
- T1055

## Analytic Stories

- Cactus Ransomware
- CISA AA24-241A
- Command And Control
- GhostRedirector IIS Module and Rungan Backdoor
- Gozi Malware
- Insider Threat
- Interlock Ransomware
- Ransomware
- Remote Monitoring and Management Software
- Scattered Lapsus$ Hunters
- Scattered Spider
- Seashell Blizzard

## Data Sources

- Sysmon EventID 17
- Sysmon EventID 18

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/named_pipes/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rmm_named_pipe.yml)*
