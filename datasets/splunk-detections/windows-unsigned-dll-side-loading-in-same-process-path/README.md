# Windows Unsigned DLL Side-Loading In Same Process Path

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies unsigned DLLs loaded through DLL side-loading with same file path with the process loaded the DLL, a technique observed in DarkGate malware. This detection monitors DLL loading, verifies signatures, and flags unsigned DLLs. Suspicious file paths and known executable associations are checked. Detecting such suspicious DLLs is crucial in preventing privilege escalation attacks and other potential security breaches. Regular security assessments, thorough monitoring, and implementing security best practices are essential in safeguarding systems from such threats.

## MITRE ATT&CK

- T1574.001

## Analytic Stories

- PlugX
- DarkGate Malware
- Derusbi
- China-Nexus Threat Activity
- Malicious Inno Setup Loader
- Salt Typhoon
- XWorm
- SnappyBee
- NailaoLocker Ransomware
- Lokibot

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.002/unsigned_dll_loaded_same_process_path/unsigned_dll_process_path.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_unsigned_dll_side_loading_in_same_process_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
