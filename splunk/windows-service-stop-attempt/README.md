# Windows Service Stop Attempt

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies attempts to stop services on a system using `net.exe`, `sc.exe` or the "Stop-Service" cmdlet. It leverages Endpoint Detection and Response (EDR) telemetry. This activity can be significant as adversaries often terminate security or critical services to evade detection and further their objectives. If confirmed malicious, this behavior could allow attackers to disable security defenses, facilitate ransomware encryption, or disrupt essential services, leading to potential data loss or system compromise.

## MITRE ATT&CK

- T1489

## Analytic Stories

- Prestige Ransomware
- Graceful Wipe Out Attack
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/prestige_ransomware/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_stop_attempt.yml)*
