# Detect Regasm with no Command Line Arguments

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects instances of regasm.exe running without command line arguments. This behavior typically indicates process injection, where another process manipulates regasm.exe. The detection leverages Endpoint Detection and Response (EDR) data, focusing on process names and command-line executions. This activity is significant as it may signal an attempt to evade detection or execute malicious code. If confirmed malicious, attackers could achieve code execution, potentially leading to privilege escalation, persistence, or access to sensitive information. Investigate network connections, parallel processes, and suspicious module loads for further context.

## MITRE ATT&CK

- T1218.009

## Analytic Stories

- Suspicious Regsvcs Regasm Activity
- Living Off The Land
- Handala Wiper

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_regasm_with_no_command_line_arguments.yml)*
