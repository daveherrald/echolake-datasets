# Windows Remote Management Execute Shell

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of winrshost.exe initiating CMD or PowerShell processes as part of a potential payload execution. winrshost.exe is associated with Windows Remote Management (WinRM) and is typically used for remote execution. By monitoring for this behavior, the detection identifies instances where winrshost.exe is leveraged to run potentially malicious commands or payloads via CMD or PowerShell. This behavior may indicate exploitation of remote management tools for unauthorized access or lateral movement within a compromised environment, signaling a potential security incident.

## MITRE ATT&CK

- T1021.006

## Analytic Stories

- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/wirm_execute_shell/winrshost_pwh.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_remote_management_execute_shell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
