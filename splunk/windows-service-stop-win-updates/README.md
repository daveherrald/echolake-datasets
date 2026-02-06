# Windows Service Stop Win Updates

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the disabling of Windows Update services, such as "Update Orchestrator Service for Windows Update," "WaaSMedicSvc," and "Windows Update." It leverages Windows System Event ID 7040 logs to identify changes in service start modes to 'disabled.' This activity is significant as it can indicate an adversary's attempt to evade defenses by preventing critical updates, leaving the system vulnerable to exploits. If confirmed malicious, this could allow attackers to maintain persistence and exploit unpatched vulnerabilities, compromising the integrity and security of the affected host.

## MITRE ATT&CK

- T1489

## Analytic Stories

- CISA AA23-347A
- RedLine Stealer

## Data Sources

- Windows Event Log System 7040

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/redline/win_update_services_stop/system.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_stop_win_updates.yml)*
