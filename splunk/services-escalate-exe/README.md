# Services Escalate Exe

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the execution of a randomly named binary via `services.exe`, indicative of privilege escalation using Cobalt Strike's `svc-exe`. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process lineage and command-line executions. This activity is significant as it often follows initial access, allowing adversaries to escalate privileges and establish persistence. If confirmed malicious, this behavior could enable attackers to execute arbitrary code, maintain long-term access, and potentially move laterally within the network, posing a severe threat to the organization's security.

## MITRE ATT&CK

- T1548

## Analytic Stories

- Graceful Wipe Out Attack
- Cobalt Strike
- CISA AA23-347A
- Compromised Windows Host
- BlackByte Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/services_escalate_exe.yml)*
