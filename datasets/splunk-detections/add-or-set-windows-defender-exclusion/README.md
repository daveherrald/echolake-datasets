# Add or Set Windows Defender Exclusion

**Type:** TTP

**Author:** Teoderick Contreras, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the use of commands to add or set exclusions
in Windows Defender. It leverages data from Endpoint Detection and Response (EDR)
agents, focusing on command-line executions involving "Add-MpPreference" or "Set-MpPreference"
with exclusion parameters. This activity is significant because adversaries often
use it to bypass Windows Defender, allowing malicious code to execute undetected.
If confirmed malicious, this behavior could enable attackers to evade antivirus
detection, maintain persistence, and execute further malicious activities without
interference from Windows Defender.


## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Compromised Windows Host
- AgentTesla
- Data Destruction
- Remcos
- CISA AA22-320A
- ValleyRAT
- XWorm
- WhisperGate
- Windows Defense Evasion Tactics
- Crypto Stealer
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/defender_exclusion_sysmon/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/add_or_set_windows_defender_exclusion.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
