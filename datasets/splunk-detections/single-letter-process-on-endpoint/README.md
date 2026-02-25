# Single Letter Process On Endpoint

**Type:** TTP

**Author:** David Dorsey, Splunk

## Description

This dataset contains sample data for detecting processes with names consisting of a single letter, which is often indicative of malware or an attacker attempting to evade detection. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because attackers use such techniques to obscure their presence and carry out malicious activities like data theft or ransomware attacks. If confirmed malicious, this behavior could lead to unauthorized access, data exfiltration, or system compromise. Immediate investigation is required to determine the legitimacy of the process.

## MITRE ATT&CK

- T1204.002

## Analytic Stories

- DHS Report TA18-074A
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204.002/single_letter_exe/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/single_letter_process_on_endpoint.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
