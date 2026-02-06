# Windows WMI Process Call Create

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of WMI command lines used to create or execute processes. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line events that include specific keywords like "process," "call," and "create." This activity is significant because adversaries often use WMI to execute malicious payloads on local or remote hosts, potentially bypassing traditional security controls. If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a severe threat to organizational security.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Volt Typhoon
- Qakbot
- IcedID
- Suspicious WMI Use
- CISA AA23-347A
- Cactus Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wmi_process_call_create.yml)*
