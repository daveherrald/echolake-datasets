# Set Default PowerShell Execution Policy To Unrestricted or Bypass

**Type:** TTP

**Author:** Steven Dick, Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting changes to the PowerShell ExecutionPolicy in the registry to "Unrestricted" or "Bypass." It leverages data from Endpoint Detection and Response (EDR) agents, focusing on registry modifications under the path *Software\Microsoft\Powershell\1\ShellIds\Microsoft.PowerShell*. This activity is significant because setting the ExecutionPolicy to these values can allow the execution of potentially malicious scripts without restriction. If confirmed malicious, this could enable an attacker to execute arbitrary code, leading to further compromise of the system and potential escalation of privileges.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- HAFNIUM Group
- Hermetic Wiper
- Credential Dumping
- Malicious PowerShell
- Data Destruction
- DarkGate Malware
- SystemBC

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_execution_policy/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
