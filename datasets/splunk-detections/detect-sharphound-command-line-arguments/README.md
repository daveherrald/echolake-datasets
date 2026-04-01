# Detect SharpHound Command-Line Arguments

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of SharpHound command-line arguments, specifically `-collectionMethod` and `invoke-bloodhound`. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant as SharpHound is commonly used for Active Directory enumeration, which can be a precursor to lateral movement or privilege escalation. If confirmed malicious, this activity could allow an attacker to map out the network, identify high-value targets, and plan further attacks, potentially compromising sensitive information and critical systems.

## MITRE ATT&CK

- T1069.001
- T1069.002
- T1087.001
- T1087.002
- T1482

## Analytic Stories

- Windows Discovery Techniques
- Ransomware
- BlackSuit Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_sharphound_command_line_arguments.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
