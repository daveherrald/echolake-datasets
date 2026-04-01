# Detect Renamed PSExec

**Type:** Hunting

**Author:** Michael Haag, Splunk, Alex Oberkircher, Github Community

## Description

This dataset contains sample data for identifying instances where `PsExec.exe` has been renamed and executed on an endpoint. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and original file names. This activity is significant because renaming `PsExec.exe` is a common tactic to evade detection. If confirmed malicious, this could allow an attacker to execute commands remotely, potentially leading to unauthorized access, lateral movement, or further compromise of the network.

## MITRE ATT&CK

- T1569.002

## Analytic Stories

- Active Directory Lateral Movement
- BlackByte Ransomware
- Cactus Ransomware
- China-Nexus Threat Activity
- CISA AA22-320A
- DarkGate Malware
- DarkSide Ransomware
- DHS Report TA18-074A
- HAFNIUM Group
- Medusa Ransomware
- Rhysida Ransomware
- Salt Typhoon
- SamSam Ransomware
- Sandworm Tools
- VanHelsing Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_renamed_psexec.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
