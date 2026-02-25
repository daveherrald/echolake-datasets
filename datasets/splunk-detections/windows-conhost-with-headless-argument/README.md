# Windows ConHost with Headless Argument

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the unusual invocation of the Windows Console Host process (conhost.exe) with the undocumented --headless parameter. This detection leverages Endpoint Detection and Response (EDR) telemetry, specifically monitoring for command-line executions where conhost.exe is executed with the --headless argument. This activity is significant for a SOC as it is not commonly used in legitimate operations and may indicate an attacker's attempt to execute commands stealthily. If confirmed malicious, this behavior could lead to persistence, lateral movement, or other malicious activities, potentially resulting in data exfiltration or system compromise.

## MITRE ATT&CK

- T1564.003
- T1564.006

## Analytic Stories

- Spearphishing Attachments
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1564.003/headless/4688_conhost_headless.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_conhost_with_headless_argument.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
