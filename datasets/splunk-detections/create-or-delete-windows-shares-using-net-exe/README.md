# Create or delete windows shares using net exe

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the creation or deletion of Windows shares using the net.exe command. It leverages Endpoint Detection and Response (EDR) data to identify processes involving net.exe with actions related to share management. This activity is significant because it may indicate an attacker attempting to manipulate network shares for malicious purposes, such as data exfiltration, malware distribution, or establishing persistence. If confirmed malicious, this activity could lead to unauthorized access to sensitive information, service disruption, or malware introduction. Immediate investigation is required to determine the intent and mitigate potential threats.

## MITRE ATT&CK

- T1070.005

## Analytic Stories

- Hidden Cobra Malware
- CISA AA22-277A
- Windows Post-Exploitation
- Prestige Ransomware
- DarkGate Malware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.005/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/create_or_delete_windows_shares_using_net_exe.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
