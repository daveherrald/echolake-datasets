# Windows Audit Policy Restored via Auditpol

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for identifying the execution of `auditpol.exe` with the "/restore" command-line argument used to restore the audit policy from a file. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity can be significant as it indicates potential defense evasion by adversaries or Red Teams, aiming to limit data that can be leveraged for detections and audits. Attackers can provide an audit policy file that disables certain or all audit policy configuration. If confirmed malicious, this behavior could allow attackers to bypass defenses, and plan further attacks, potentially leading to full machine compromise or lateral movement.

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

*Source: [Splunk Security Content](detections/endpoint/windows_audit_policy_restored_via_auditpol.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
