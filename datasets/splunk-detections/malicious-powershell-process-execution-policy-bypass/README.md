# Malicious PowerShell Process - Execution Policy Bypass

**Type:** Anomaly

**Author:** Rico Valdez, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting PowerShell processes initiated with parameters that bypass the local execution policy for scripts. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions containing specific flags like "-ex" or "bypass." This activity is significant because bypassing execution policies is a common tactic used by attackers to run malicious scripts undetected. If confirmed malicious, this could allow an attacker to execute arbitrary code, potentially leading to further system compromise, data exfiltration, or persistent access within the environment.

## MITRE ATT&CK

- T1059.001

## Analytic Stories

- DHS Report TA18-074A
- Volt Typhoon
- China-Nexus Threat Activity
- AsyncRAT
- HAFNIUM Group
- Salt Typhoon
- XWorm
- DarkCrystal RAT
- 0bj3ctivity Stealer
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/encoded_powershell/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/malicious_powershell_process___execution_policy_bypass.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
