# Windows Audit Policy Disabled via Legacy Auditpol

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic identifies the execution of the legacy `auditpol.exe` included with the Windows 2000 Resource Kit Tools, with the "/disable" command-line argument or one of the allowed category flags and the "none" option, in order to disable a specific logging category from the audit policy. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity can be significant as it indicates potential defense evasion by adversaries or Red Teams, aiming to limit data that can be leveraged for detections and audits. If confirmed malicious, this behavior could allow attackers to bypass defenses, and plan further attacks, potentially leading to full machine compromise or lateral movement.

## MITRE ATT&CK

- T1562.002

## Analytic Stories

- Windows Audit Policy Tampering

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_audit_policy_disabled_via_legacy_auditpol.yml)*
