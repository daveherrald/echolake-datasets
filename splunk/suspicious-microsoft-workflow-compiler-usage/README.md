# Suspicious microsoft workflow compiler usage

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the usage of microsoft.workflow.compiler.exe, a rarely utilized executable typically found in C:\Windows\Microsoft.NET\Framework64\v4.0.30319. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution telemetry. The significance of this activity lies in its uncommon usage, which may indicate malicious intent such as code execution or persistence mechanisms. If confirmed malicious, an attacker could leverage this process to execute arbitrary code, potentially leading to unauthorized access or further compromise of the system.

## MITRE ATT&CK

- T1127

## Analytic Stories

- Trusted Developer Utilities Proxy Execution
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1127/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_microsoft_workflow_compiler_usage.yml)*
