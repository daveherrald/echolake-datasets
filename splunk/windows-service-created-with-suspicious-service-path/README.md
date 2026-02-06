# Windows Service Created with Suspicious Service Path

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

The following analytic detects the creation of a Windows Service with a binary path located in uncommon directories, using Windows Event ID 7045. It leverages logs from the `wineventlog_system` to identify services installed outside typical system directories. This activity is significant as adversaries, including those deploying Clop ransomware, often create malicious services for lateral movement, remote code execution, persistence, and execution. If confirmed malicious, this could allow attackers to maintain persistence, execute arbitrary code, and potentially escalate privileges, posing a severe threat to the environment.

## MITRE ATT&CK

- T1569.002

## Analytic Stories

- PlugX
- Qakbot
- China-Nexus Threat Activity
- CISA AA23-347A
- Flax Typhoon
- Derusbi
- Salt Typhoon
- Active Directory Lateral Movement
- Snake Malware
- Clop Ransomware
- Crypto Stealer
- Brute Ratel C4
- APT37 Rustonotto and FadeStealer

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/windows_service_created_with_suspicious_service_path/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_created_with_suspicious_service_path.yml)*
