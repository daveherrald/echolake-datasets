# Windows Command and Scripting Interpreter Path Traversal Exec

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects path traversal command-line execution, often used in malicious documents to execute code via msdt.exe for defense evasion. It leverages Endpoint Detection and Response (EDR) data, focusing on specific patterns in process paths. This activity is significant as it can indicate an attempt to bypass security controls and execute unauthorized code. If confirmed malicious, this behavior could lead to code execution, privilege escalation, or persistence within the environment, potentially allowing attackers to deploy malware or leverage other living-off-the-land binaries (LOLBins).

## MITRE ATT&CK

- T1059

## Analytic Stories

- Microsoft Support Diagnostic Tool Vulnerability CVE-2022-30190
- Compromised Windows Host
- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/path_traversal/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_command_and_scripting_interpreter_path_traversal_exec.yml)*
