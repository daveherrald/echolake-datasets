# Windows Suspicious Driver Loaded Path

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the loading of drivers from suspicious paths, which is a technique often used by malicious software such as coin miners (e.g., xmrig). It leverages Sysmon EventCode 6 to identify drivers loaded from non-standard directories. This activity is significant because legitimate drivers typically reside in specific system directories, and deviations may indicate malicious activity. If confirmed malicious, this could allow an attacker to execute code at the kernel level, potentially leading to privilege escalation, persistence, or further system compromise.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- XMRig
- CISA AA22-320A
- AgentTesla
- BlackByte Ransomware
- Snake Keylogger
- Interlock Ransomware
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 6

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_suspicious_driver_loaded_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
