# Windows WMI Process And Service List

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies suspicious WMI command lines querying for running processes or services. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific process and command-line events. This activity is significant as adversaries often use WMI to gather system information and identify services on compromised machines. If confirmed malicious, this behavior could allow attackers to map out the system, identify critical services, and plan further attacks, potentially leading to privilege escalation or persistence within the environment.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Windows Post-Exploitation
- Prestige Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/winpeas/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wmi_process_and_service_list.yml)*
