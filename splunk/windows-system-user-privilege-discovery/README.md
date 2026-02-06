# Windows System User Privilege Discovery

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of `whoami.exe` with the `/priv` parameter, which displays the privileges assigned to the current user account. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as it may indicate an adversary attempting to enumerate user privileges, a common step in the reconnaissance phase of an attack. If confirmed malicious, this could lead to privilege escalation or further exploitation within the environment.

## MITRE ATT&CK

- T1033

## Analytic Stories

- CISA AA23-347A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/whoami_priv/whoami-priv-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_user_privilege_discovery.yml)*
