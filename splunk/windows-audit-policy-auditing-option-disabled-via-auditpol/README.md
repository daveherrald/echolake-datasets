# Windows Audit Policy Auditing Option Disabled via Auditpol

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic identifies the execution of `auditpol.exe` with the "/set", "/option" and "/value:disable" command-line arguments used to disable specific auditing options of the audit policy. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity can be significant as it indicates potential defense evasion by adversaries or Red Teams, aiming to limit data that can be leveraged for detections and audits. If confirmed malicious, this behavior could allow attackers to bypass defenses, and plan further attacks, potentially leading to full machine compromise or lateral movement.

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

*Source: [Splunk Security Content](detections/endpoint/windows_audit_policy_auditing_option_disabled_via_auditpol.yml)*
