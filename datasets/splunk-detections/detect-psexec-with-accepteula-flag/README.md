# Detect PsExec With accepteula Flag

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying the execution of `PsExec.exe` with the `accepteula` flag in the command line. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. This activity is significant because PsExec is commonly used by threat actors to execute code on remote systems, and the `accepteula` flag indicates first-time usage, which could signify initial compromise. If confirmed malicious, this activity could allow attackers to gain remote code execution capabilities, potentially leading to further system compromise and lateral movement within the network.

## MITRE ATT&CK

- T1021.002

## Analytic Stories

- DHS Report TA18-074A
- Active Directory Lateral Movement
- HAFNIUM Group
- Rhysida Ransomware
- Medusa Ransomware
- DarkSide Ransomware
- SamSam Ransomware
- CISA AA22-320A
- Sandworm Tools
- IcedID
- BlackByte Ransomware
- DarkGate Malware
- Cactus Ransomware
- Volt Typhoon
- Seashell Blizzard
- VanHelsing Ransomware
- Storm-0501 Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.002/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_psexec_with_accepteula_flag.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
