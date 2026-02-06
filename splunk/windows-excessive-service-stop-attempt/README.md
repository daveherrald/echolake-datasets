# Windows Excessive Service Stop Attempt

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects multiple attempts to stop or delete services on a system using `net.exe` or `sc.exe`. It leverages Endpoint Detection and Response (EDR) telemetry, focusing on process names and command-line executions within a one-minute window. This activity is significant as it may indicate an adversary attempting to disable security or critical services to evade detection and further their objectives. If confirmed malicious, this could lead to the attacker gaining persistence, escalating privileges, or disrupting essential services, thereby compromising the system's security posture.

## MITRE ATT&CK

- T1489

## Analytic Stories

- XMRig
- Ransomware
- BlackByte Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_excessive_service_stop_attempt.yml)*
