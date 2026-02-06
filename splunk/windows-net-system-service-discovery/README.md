# Windows Net System Service Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the enumeration of Windows services using the net start command, which is a built-in utility that lists all running services on a system. Adversaries, system administrators, or automated tools may use this command to gain situational awareness of what services are active, identify potential security software, or discover opportunities for privilege escalation and lateral movement. The execution of net start is often associated with reconnaissance activity during the early stages of an intrusion, as attackers attempt to map out the system’s defense mechanisms and operational services. By monitoring process execution for instances of cmd.exe /c net start or similar command-line usage, defenders can detect potentially suspicious activity. Correlating this behavior with other reconnaissance commands, such as tasklist or sc query, strengthens detection fidelity. While net start is not inherently malicious, unusual or repeated use in non-administrative contexts should be flagged for further investigation.

## MITRE ATT&CK

- T1007

## Analytic Stories

- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/lamehug/T1007/net_start/net_start.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_net_system_service_discovery.yml)*
