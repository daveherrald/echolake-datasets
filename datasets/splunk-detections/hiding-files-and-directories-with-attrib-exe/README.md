# Hiding Files And Directories With Attrib exe

**Type:** TTP

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for detecting the use of the Windows binary attrib.exe to hide files or directories by marking them with specific flags. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line arguments that include the "+h" flag. This activity is significant because hiding files can be a tactic used by attackers to conceal malicious files or tools from users and security software. If confirmed malicious, this behavior could allow an attacker to persist in the environment undetected, potentially leading to further compromise or data exfiltration.

## MITRE ATT&CK

- T1222.001

## Analytic Stories

- Windows Persistence Techniques
- Malicious Inno Setup Loader
- Azorult
- Compromised Windows Host
- Windows Defense Evasion Tactics
- Crypto Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/hiding_files_and_directories_with_attrib_exe.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
