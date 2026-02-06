# Windows PUA Named Pipe

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

The following analytic detects the creation or connection to named pipes  used by potentially unwanted applications (PUAs) like VPNs or utilities like PsExec.
It leverages Sysmon EventCodes 17 and 18.
If confirmed malicious, this could allow an attacker to abuse these to potentially gain persistence, command and control, or further system compromise.


## MITRE ATT&CK

- T1559
- T1021.002
- T1055

## Analytic Stories

- Active Directory Lateral Movement
- BlackByte Ransomware
- Cactus Ransomware
- CISA AA22-320A
- DarkGate Malware
- DarkSide Ransomware
- DHS Report TA18-074A
- HAFNIUM Group
- IcedID
- Medusa Ransomware
- Rhysida Ransomware
- SamSam Ransomware
- Sandworm Tools
- Seashell Blizzard
- VanHelsing Ransomware
- Volt Typhoon

## Data Sources

- Sysmon EventID 17
- Sysmon EventID 18

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/named_pipes/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_pua_named_pipe.yml)*
