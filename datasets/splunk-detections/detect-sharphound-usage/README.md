# Detect SharpHound Usage

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the usage of the SharpHound binary by identifying its original filename, `SharpHound.exe`, and the process name. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process metadata and command-line executions. SharpHound is a tool used for Active Directory enumeration, often by attackers during the reconnaissance phase. If confirmed malicious, this activity could allow an attacker to map out the network, identify high-value targets, and plan further attacks, potentially leading to privilege escalation and lateral movement within the environment.

## MITRE ATT&CK

- T1069.001
- T1069.002
- T1087.001
- T1087.002
- T1482

## Analytic Stories

- Windows Discovery Techniques
- Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_sharphound_usage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
