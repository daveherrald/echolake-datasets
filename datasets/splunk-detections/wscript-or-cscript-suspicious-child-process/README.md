# Wscript Or Cscript Suspicious Child Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This analytic identifies a suspicious spawned process by WScript or CScript process. This technique was a common technique used by adversaries and malware to execute different LOLBIN, other scripts like PowerShell or spawn a suspended process to inject its code as a defense evasion. This TTP may detect some normal script that uses several application tools that are in the list of the child process it detects but a good pivot and indicator that a script may execute suspicious code.

## MITRE ATT&CK

- T1055
- T1134.004
- T1543

## Analytic Stories

- Data Destruction
- FIN7
- NjRAT
- Remcos
- XWorm
- WhisperGate
- Unusual Processes
- ShrinkLocker
- 0bj3ctivity Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.005/vbs_wscript/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/wscript_or_cscript_suspicious_child_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
