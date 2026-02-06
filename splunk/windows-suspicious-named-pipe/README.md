# Windows Suspicious Named Pipe

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

The following analytic detects the creation or connection to known suspicious named pipes.
It leverages Sysmon EventCodes 17 and 18 to identify known default pipe names used by malicious or suspicious tools.
If confirmed malicious, this could allow an attacker to abuse these to potentially gain privilege escalation, 
persistence, c2 communications, or further system compromise.


## MITRE ATT&CK

- T1559
- T1021.002
- T1055

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- BlackByte Ransomware
- Brute Ratel C4
- Cobalt Strike
- DarkSide Ransomware
- Gozi Malware
- Graceful Wipe Out Attack
- Hellcat Ransomware
- LockBit Ransomware
- Meterpreter
- Remote Monitoring and Management Software
- Trickbot
- Tuoni

## Data Sources

- Sysmon EventID 17
- Sysmon EventID 18

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/named_pipes/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_suspicious_named_pipe.yml)*
