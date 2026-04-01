# Create Remote Thread In Shell Application

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting suspicious process injection in command shell applications, specifically targeting `cmd.exe` and `powershell.exe`. It leverages Sysmon EventCode 8 to identify the creation of remote threads within these shell processes. This activity is significant because it is a common technique used by malware, such as IcedID, to inject malicious code and execute it within legitimate processes. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a severe threat to system security.

## MITRE ATT&CK

- T1055

## Analytic Stories

- IcedID
- Qakbot
- Warzone RAT

## Data Sources

- Sysmon EventID 8

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/simulated_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/create_remote_thread_in_shell_application.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
