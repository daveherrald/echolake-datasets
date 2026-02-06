# Windows Audit Policy Auditing Option Modified - Registry

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Bhavin Patel, Splunk

## Description

The following analytic detects potentially suspicious modifications to the Audit Policy auditing options registry values. It leverages data from the Endpoint.Registry data model, focusing on changes to one of the following auditing option values "CrashOnAuditFail", "FullPrivilegeAuditing", "AuditBaseObjects" and "AuditBaseDirectories" within the "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\" registry key. This activity is significant as it could be a sign of a threat actor trying to tamper with the audit policy configuration, and disabling SACLs configuration. If confirmed malicious, this behavior could allow attackers to bypass defenses, and plan further attacks, potentially leading to full machine compromise or lateral movement.

## MITRE ATT&CK

- T1547.014

## Analytic Stories

- Windows Audit Policy Tampering

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.002/auditpol_tampering/auditpol_tampering_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_audit_policy_auditing_option_modified___registry.yml)*
