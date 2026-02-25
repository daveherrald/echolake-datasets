# Windows Service Created with Suspicious Service Name

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting the creation of a Windows Service with a known suspicious or malicious name using Windows Event ID 7045. It leverages logs from the `wineventlog_system` to identify these services installations. This activity is significant as adversaries, including those deploying Clop ransomware, often create malicious services for lateral movement, remote code execution, persistence, and execution. If confirmed malicious, this could allow attackers to maintain persistence, execute arbitrary code, and potentially escalate privileges, posing a severe threat to the environment.

## MITRE ATT&CK

- T1569.002

## Analytic Stories

- Active Directory Lateral Movement
- Brute Ratel C4
- CISA AA23-347A
- Clop Ransomware
- Flax Typhoon
- PlugX
- Qakbot
- Snake Malware
- Tuoni

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/sliver/sliver_windows-system.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_created_with_suspicious_service_name.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
