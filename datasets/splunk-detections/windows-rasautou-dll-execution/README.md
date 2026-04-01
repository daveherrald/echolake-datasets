# Windows Rasautou DLL Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of an arbitrary DLL by the Windows Remote Auto Dialer (rasautou.exe). This behavior is identified by analyzing process creation events where rasautou.exe is executed with specific command-line arguments. This activity is significant because it leverages a Living Off The Land Binary (LOLBin) to execute potentially malicious code, bypassing traditional security controls. If confirmed malicious, this technique could allow an attacker to execute arbitrary code, potentially leading to system compromise, privilege escalation, or persistent access within the environment.

## MITRE ATT&CK

- T1055.001
- T1218

## Analytic Stories

- Compromised Windows Host
- Windows Defense Evasion Tactics
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055.001/rasautou/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rasautou_dll_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
