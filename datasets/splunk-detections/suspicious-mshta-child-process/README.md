# Suspicious mshta child process

**Type:** TTP

**Author:** Michael Haag, Teoderick Contreras Splunk

## Description

This dataset contains sample data for identifying child processes spawned from "mshta.exe". It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific child processes like "powershell.exe" and "cmd.exe". This activity is significant because "mshta.exe" is often exploited by attackers to execute malicious scripts or commands. If confirmed malicious, this behavior could allow an attacker to execute arbitrary code, escalate privileges, or maintain persistence within the environment. Monitoring this activity helps in early detection of potential threats leveraging "mshta.exe" for malicious purposes.

## MITRE ATT&CK

- T1218.005

## Analytic Stories

- Suspicious MSHTA Activity
- Living Off The Land
- Lumma Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.005/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_mshta_child_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
