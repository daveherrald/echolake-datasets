# Windows Command and Scripting Interpreter Hunting Path Traversal

**Type:** Hunting

**Author:** Teoderick Contreras, Michael Haag, Splunk

## Description

The following analytic identifies path traversal command-line executions,
leveraging data from Endpoint Detection and Response (EDR) agents. It detects patterns
in command-line arguments indicative of path traversal techniques, such as multiple
instances of "/..", "\..", or "\\..". This activity is significant as it often indicates
attempts to evade defenses by executing malicious code, such as through msdt.exe.
If confirmed malicious, this behavior could allow attackers to execute arbitrary
code, potentially leading to system compromise, data exfiltration, or further lateral
movement within the network.


## MITRE ATT&CK

- T1059

## Analytic Stories

- Windows Defense Evasion Tactics
- Microsoft Support Diagnostic Tool Vulnerability CVE-2022-30190

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/path_traversal/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_command_and_scripting_interpreter_hunting_path_traversal.yml)*
