# Detect Path Interception By Creation Of program exe

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for identifying the creation of a program executable in an unquoted service path, a common technique for privilege escalation. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events where the parent process is 'services.exe'. This activity is significant because unquoted service paths can be exploited by attackers to execute arbitrary code with elevated privileges. If confirmed malicious, this could allow an attacker to gain higher-level access, potentially leading to full system compromise and persistent control over the affected endpoint.

## MITRE ATT&CK

- T1574.009

## Analytic Stories

- Windows Persistence Techniques
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1574.009/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_path_interception_by_creation_of_program_exe.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
