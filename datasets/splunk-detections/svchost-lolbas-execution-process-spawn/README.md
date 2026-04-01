# Svchost LOLBAS Execution Process Spawn

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting instances of 'svchost.exe' spawning Living Off The Land Binaries and Scripts (LOLBAS) processes. It leverages Endpoint Detection and Response (EDR) data to monitor child processes of 'svchost.exe' that match known LOLBAS executables. This activity is significant as adversaries often use LOLBAS techniques to execute malicious code stealthily, potentially indicating lateral movement or code execution attempts. If confirmed malicious, this behavior could allow attackers to execute arbitrary commands, escalate privileges, or maintain persistence within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1053.005

## Analytic Stories

- Active Directory Lateral Movement
- Living Off The Land
- Scheduled Tasks
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053.005/svchost_lolbas_execution_process_spawn/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/svchost_lolbas_execution_process_spawn.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
