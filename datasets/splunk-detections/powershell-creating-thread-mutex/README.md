# Powershell Creating Thread Mutex

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of PowerShell scripts using the `mutex` function via EventCode 4104. This detection leverages PowerShell Script Block Logging to identify scripts that create thread mutexes, a technique often used in obfuscated scripts to ensure only one instance runs on a compromised machine. This activity is significant as it may indicate the presence of sophisticated malware or persistence mechanisms. If confirmed malicious, the attacker could maintain exclusive control over a process, potentially leading to further exploitation or persistence within the environment.

## MITRE ATT&CK

- T1027.005
- T1059.001

## Analytic Stories

- Malicious PowerShell
- Water Gamayun

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_creating_thread_mutex.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
