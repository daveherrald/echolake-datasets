# Windows Disable or Stop Browser Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of the taskkill command in a process command line to terminate several known browser processes, a technique commonly employed by the Braodo stealer malware to steal credentials. By forcefully closing browsers like Chrome, Edge, and Firefox, the malware can unlock files that store sensitive information, such as passwords and login data. This detection focuses on identifying taskkill commands targeting these browsers, signaling malicious intent. Early detection allows security teams to investigate and prevent further credential theft and system compromise.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Braodo Stealer
- Scattered Lapsus$ Hunters
- Hellcat Ransomware
- Castle RAT

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/taskkill_browser/braodo_taskkill.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_disable_or_stop_browser_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
