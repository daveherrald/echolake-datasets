# Windows Audit Policy Security Descriptor Tampering via Auditpol

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for identifying the execution of `auditpol.exe` with the "/set" flag, and "/sd" command-line arguments used to modify the security descriptor of the audit policy. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity can be significant as it indicates potential defense evasion by adversaries or Red Teams, aiming to limit data that can be leveraged for detections and audits. An attacker, can disable certain policy categories from logging and then change the security descriptor in order to restrict access to certain users or application from reverting their changes. If confirmed malicious, this behavior could allow attackers to bypass defenses, and plan further attacks, potentially leading to full machine compromise or lateral movement.

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

*Source: [Splunk Security Content](detections/endpoint/windows_audit_policy_security_descriptor_tampering_via_auditpol.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
